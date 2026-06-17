#include "port_scanner.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <cstdio>

static void detect_frida_processes(void);

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Avoid libc: use raw constants and minimal struct for syscall args
#define AF_INET      2
#define SOCK_STREAM  1
#define IPPROTO_TCP  6
#define SOL_SOCKET   1
#define SO_RCVTIMEO  20
#define SO_SNDTIMEO  21
#define O_RDONLY     0

#define CONNECT_TIMEOUT_SEC 2
#define DBUS_PROBE_TIMEOUT_SEC 1
#define MSG_DONTWAIT 0x40
#define MAX_LISTEN_PORTS 16
#define MAX_DBUS_DETAILS 4

// Minimal sockaddr_in layout for kernel (network byte order)
struct sockaddr_in_min {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  pad[8];
};

static inline unsigned short host_to_net_short(unsigned short v) {
    return (unsigned short)((v >> 8) | (v << 8));
}

// 将 pid 转为十进制字符串写入 buf，避免使用 libc sprintf
static void pid_to_str(int pid, char *buf, size_t buf_len) {
    if (buf_len < 2) return;
    if (pid <= 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }
    char tmp[16];
    int i = 0;
    unsigned int u = (unsigned int)pid;
    while (u && i < 15) {
        tmp[i++] = (char)('0' + (u % 10));
        u /= 10;
    }
    size_t j = 0;
    while (i > 0 && j < buf_len - 1) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
}

// 检测是否存在进程名包含 "frida-server" 且该进程在 net/tcp 中有 LISTEN(0A)
// 用于覆盖 Frida 16+ 使用随机端口 (-l 0.0.0.0:0) 的情况
static bool detect_frida_server_listening(void) {
    char path[64];
    char comm[32];
    char tcp_buf[2048];
    const char prefix_proc[] = "/proc/";
    const char suffix_comm[] = "/comm";
    const char suffix_net_tcp[] = "/net/tcp";
    const char needle[] = "frida-server";
    const char listen_state[] = " 0A ";  // TCP LISTEN in /proc/net/tcp

    for (int pid = 1; pid < 32768 && pid > 0; pid++) {
        my_memset(path, 0, sizeof(path));
        my_strcpy(path, prefix_proc);
        pid_to_str(pid, path + sizeof(prefix_proc) - 1, sizeof(path) - (sizeof(prefix_proc) - 1));
        size_t plen = my_strlen(path);
        if (plen + sizeof(suffix_comm) >= sizeof(path)) continue;
        my_strcpy(path + plen, suffix_comm);

        int fd = my_open(path, O_RDONLY, 0);
        if (fd < 0) continue;

        my_memset(comm, 0, sizeof(comm));
        ssize_t n = my_read(fd, comm, sizeof(comm) - 1);
        my_close(fd);
        if (n <= 0) continue;

        comm[n] = '\0';
        while (n > 0 && (comm[n - 1] == '\n' || comm[n - 1] == '\r')) {
            comm[--n] = '\0';
        }
        if (my_strstr(comm, needle) == nullptr) continue;

        path[plen] = '\0';
        if (plen + sizeof(suffix_net_tcp) >= sizeof(path)) continue;
        my_strcpy(path + plen, suffix_net_tcp);

        fd = my_open(path, O_RDONLY, 0);
        if (fd < 0) continue;

        n = my_read(fd, tcp_buf, sizeof(tcp_buf) - 1);
        my_close(fd);
        if (n <= 0) continue;

        tcp_buf[n] = '\0';
        if (my_strstr(tcp_buf, listen_state) != nullptr) {
            LOGD("frida-server process (pid=%d) has LISTEN socket", pid);
            return true;
        }
    }
    return false;
}

// Frida 默认端口 27042；IDA 动态调试 android_server 默认监听 23946（端口转发后 PC 端 IDA 连接）
static const int FRIDA_PORT = 27042;
static const int IDA_ANDROID_SERVER_PORT = 23946;
static const int SUSPICIOUS_DEBUG_PORTS[] = { FRIDA_PORT, IDA_ANDROID_SERVER_PORT, 0 };

// Last scan result for JNI to build DetectionResult (title/summary/details)
#define MAX_OPEN_PORTS 8
static int s_open_ports[MAX_OPEN_PORTS];
static int s_open_port_count = 0;

#define MAX_FRIDA_PROCESS_DETAILS 8
static char s_frida_process_details[MAX_FRIDA_PROCESS_DETAILS][256];
static int s_frida_process_count = 0;

/* D-Bus AUTH 探测：frida-server 暴露 frida-core，发送 AUTH 会回 REJECT */
static char s_dbus_details[MAX_DBUS_DETAILS][256];
static int s_dbus_detail_count = 0;

/* 从 /proc/net/tcp 解析本机可达 LISTEN(0A) 端口（127.0.0.1 或 INADDR_ANY），
 * 写入 ports[]，返回数量，最多 max_ports。
 *
 * 历史问题：旧实现只看 0100007F（127.0.0.1）。Frida 16+ 常通过
 *   frida-server -l 0.0.0.0:0
 * 绑定全部接口，对应 /proc/net/tcp 中本地地址 00000000 → D-Bus 探测会全部漏过。
 * 现增加 INADDR_ANY（00000000）的同等解析。 */
static int parse_listen_ports_localhost(int *ports, int max_ports) {
    int fd = my_open("/proc/net/tcp", O_RDONLY, 0);
    if (fd < 0) return 0;
    char buffer[4096];
    ssize_t n = my_read(fd, buffer, sizeof(buffer) - 1);
    my_close(fd);
    if (n <= 0) return 0;
    buffer[n] = '\0';

    const char *needle_listen   = " 0A ";
    const char *needle_loopback = "0100007F:";  /* 127.0.0.1 */
    const char *needle_anyaddr  = "00000000:";  /* INADDR_ANY (0.0.0.0) */
    int count = 0;
    const char *line = buffer;
    while (*line && count < max_ports) {
        const char *eol = my_strstr(line, "\n");
        const char *end = eol ? eol : (line + my_strlen(line));
        if (end > line && my_strstr(line, needle_listen) != nullptr) {
            const char *addr = my_strstr(line, needle_loopback);
            int skip = 9;  /* len("0100007F:") == len("00000000:") == 9 */
            if (addr == nullptr) {
                addr = my_strstr(line, needle_anyaddr);
                /* 0.0.0.0 也可能出现在 rem_address；需保证它在行首 local_address 字段。
                 * /proc/net/tcp 格式: "  N: LOCAL REMOTE STATE..."，local 段在第 2 个 token。
                 * 简化处理：只接受 00000000:XXXX 距离行首 < 30 的命中（local_address 区间），
                 * 远端地址通常在更靠后位置，跨距过远直接丢弃以降低误报。 */
                if (addr != nullptr && (size_t)(addr - line) > 30) addr = nullptr;
            }
            if (addr != nullptr) {
                addr += skip;
                int port_hex = 0;
                while (*addr && *addr != ' ' && *addr != '\n') {
                    int v = (*addr >= '0' && *addr <= '9') ? (*addr - '0') :
                            (*addr >= 'A' && *addr <= 'F') ? (*addr - 'A' + 10) :
                            (*addr >= 'a' && *addr <= 'f') ? (*addr - 'a' + 10) : -1;
                    if (v < 0) break;
                    port_hex = (port_hex << 4) | v;
                    addr++;
                }
                if (port_hex > 0 && port_hex <= 65535) {
                    /* 去重：同一端口可能同时以 0.0.0.0/127.0.0.1 出现 */
                    int dup = 0;
                    for (int i = 0; i < count; i++) {
                        if (ports[i] == port_hex) { dup = 1; break; }
                    }
                    if (!dup) ports[count++] = port_hex;
                }
            }
        }
        if (!eol) break;
        line = eol + 1;
    }
    return count;
}

/* 对 127.0.0.1:port 发 D-Bus AUTH 探测；收到 REJECT 则高度疑似 frida-server */
static bool probe_dbus_frida(int port) {
    int sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval_min {
        long tv_sec;
        long tv_usec;
    } tv;
    tv.tv_sec = DBUS_PROBE_TIMEOUT_SEC;
    tv.tv_usec = 0;
    my_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, (unsigned int)sizeof(tv));
    my_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, (unsigned int)sizeof(tv));

    struct sockaddr_in_min addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = host_to_net_short((unsigned short)port);
    addr.sin_addr   = 0x0100007f;

    if (my_connect(sock, &addr, (unsigned int)sizeof(addr)) != 0) {
        my_close(sock);
        return false;
    }
    const char auth_byte = '\x00';
    const char auth_line[] = "AUTH\r\n";
    if (my_send(sock, &auth_byte, 1, 0) != 1) {
        my_close(sock);
        return false;
    }
    if (my_send(sock, auth_line, 6, 0) != 6) {
        my_close(sock);
        return false;
    }
    char buf[16];
    my_memset(buf, 0, sizeof(buf));
    ssize_t nr = my_recv(sock, buf, 8, MSG_DONTWAIT);
    my_close(sock);
    if (nr < 6) return false;
    if (my_strstr(buf, "REJECT") != nullptr) {
        LOGD("D-Bus REJECT on 127.0.0.1:%d - frida-server suspected", port);
        return true;
    }
    return false;
}

static void detect_dbus_frida_server(void) {
    s_dbus_detail_count = 0;
    int listen_ports[MAX_LISTEN_PORTS];
    int n = parse_listen_ports_localhost(listen_ports, MAX_LISTEN_PORTS);
    for (int i = 0; i < n && s_dbus_detail_count < MAX_DBUS_DETAILS; i++) {
        int port = listen_ports[i];
        if (port <= 0) continue;
        if (probe_dbus_frida(port)) {
            char *d = s_dbus_details[s_dbus_detail_count];
            size_t pos = 0;
            const char prefix[] = "D-Bus frida-server (REJECT) on 127.0.0.1:";
            while (prefix[pos] && pos < 200) { d[pos] = prefix[pos]; pos++; }
            /* port 转十进制字符串（无前导零） */
            char port_buf[8];
            int i = 0, p = port;
            if (p == 0) port_buf[i++] = '0';
            else {
                unsigned int u = (unsigned int)p;
                while (u && i < 7) { port_buf[i++] = (char)('0' + (u % 10)); u /= 10; }
            }
            while (i > 0 && pos < 254) d[pos++] = port_buf[--i];
            d[pos] = '\0';
            s_dbus_detail_count++;
        }
    }
}

bool is_port_open(int port) {
    int sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval_min {
        long tv_sec;
        long tv_usec;
    } tv;
    tv.tv_sec = CONNECT_TIMEOUT_SEC;
    tv.tv_usec = 0;
    my_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, (unsigned int)sizeof(tv));
    my_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, (unsigned int)sizeof(tv));

    struct sockaddr_in_min addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = host_to_net_short((unsigned short)port);
    addr.sin_addr   = 0x0100007f; /* 127.0.0.1 in network byte order */

    int result = my_connect(sock, &addr, (unsigned int)sizeof(addr));
    my_close(sock);
    return (result == 0);
}

bool detect_frida_ports(void) {
    s_open_port_count = 0;
    bool found = false;

    for (int i = 0; SUSPICIOUS_DEBUG_PORTS[i] != 0 && s_open_port_count < MAX_OPEN_PORTS; i++) {
        int port = SUSPICIOUS_DEBUG_PORTS[i];
        if (is_port_open(port)) {
            LOGD("Suspicious port detected: %d", port);
            s_open_ports[s_open_port_count++] = port;
            found = true;
        }
    }

    /* 系统 net/tcp 中 LISTEN(0A) 行：Frida 27042(0x699A)、IDA android_server 23946(0x5D8A)；边界匹配 ":699A "/":5D8A " 避免误报 */
    const char *net_tcp_path = "/proc/net/tcp";
    int fd = my_open(net_tcp_path, O_RDONLY, 0);
    if (fd >= 0) {
        char buffer[4096];
        ssize_t n = my_read(fd, buffer, sizeof(buffer) - 1);
        my_close(fd);
        if (n > 0 && s_open_port_count < MAX_OPEN_PORTS) {
            buffer[n] = '\0';
            const char *line = buffer;
            while (*line) {
                const char *eol = my_strstr(line, "\n");
                if (eol && eol > line && my_strstr(line, " 0A ") != nullptr) {
                    int add_port = -1;
                    if (my_strstr(line, ":699A ") != nullptr) add_port = 27042;
                    else if (my_strstr(line, ":5D8A ") != nullptr) add_port = 23946;
                    if (add_port > 0) {
                        int j;
                        for (j = 0; j < s_open_port_count; j++) if (s_open_ports[j] == add_port) break;
                        if (j >= s_open_port_count) {
                            s_open_ports[s_open_port_count++] = add_port;
                            LOGD("Port %d (LISTEN) in %s", add_port, net_tcp_path);
                            found = true;
                        }
                    }
                }
                if (!eol) break;
                line = eol + 1;
            }
        }
    }

    /* Frida 16+ 随机端口：检测是否有进程名包含 frida-server 且该进程有 TCP LISTEN */
    if (s_open_port_count < MAX_OPEN_PORTS && detect_frida_server_listening()) {
        found = true;
        s_open_ports[s_open_port_count++] = 0;  /* 0 表示「frida-server 进程 + 监听」，非端口号 */
    }

    /* Frida 进程：扫描 /proc/[pid]/comm，检测 re.frida.helper、re.frida.server 等（Frida 运行时会留下进程） */
    detect_frida_processes();
    if (s_frida_process_count > 0) found = true;

    /* D-Bus AUTH 探测：对 127.0.0.1 上 LISTEN 端口发 AUTH，收到 REJECT 则疑似 frida-server */
    detect_dbus_frida_server();
    if (s_dbus_detail_count > 0) found = true;

    return found;
}

int get_frida_dbus_detail_count(void) {
    return s_dbus_detail_count;
}

const char *get_frida_dbus_detail_at(int index) {
    if (index < 0 || index >= s_dbus_detail_count) return nullptr;
    return s_dbus_details[index];
}

// Frida 进程名关键词：re.frida 匹配 re.frida.helper/re.frida.server（comm 最长 15 字符）；frida-server 独立匹配
static const char *FRIDA_PROCESS_KEYWORDS[] = {
    "re.frida", "frida-server", nullptr
};

/* 扫描 /proc/[pid]/comm 检测 Frida 相关进程（re.frida.helper、re.frida.server 等） */
static void detect_frida_processes(void) {
    char path[64];
    char comm[32];
    const char prefix_proc[] = "/proc/";
    const char suffix_comm[] = "/comm";

    s_frida_process_count = 0;
    my_memset(s_frida_process_details, 0, sizeof(s_frida_process_details));

    for (int pid = 1; pid < 32768 && pid > 0 && s_frida_process_count < MAX_FRIDA_PROCESS_DETAILS; pid++) {
        my_memset(path, 0, sizeof(path));
        my_strcpy(path, prefix_proc);
        pid_to_str(pid, path + sizeof(prefix_proc) - 1, sizeof(path) - (sizeof(prefix_proc) - 1));
        size_t plen = my_strlen(path);
        if (plen + sizeof(suffix_comm) >= sizeof(path)) continue;
        my_strcpy(path + plen, suffix_comm);

        int fd = my_open(path, O_RDONLY, 0);
        if (fd < 0) continue;

        my_memset(comm, 0, sizeof(comm));
        ssize_t n = my_read(fd, comm, sizeof(comm) - 1);
        my_close(fd);
        if (n <= 0) continue;

        comm[n] = '\0';
        while (n > 0 && (comm[n - 1] == '\n' || comm[n - 1] == '\r')) {
            comm[--n] = '\0';
        }
        if (n <= 0) continue;

        for (int i = 0; FRIDA_PROCESS_KEYWORDS[i] != nullptr; i++) {
            if (my_strstr(comm, FRIDA_PROCESS_KEYWORDS[i]) != nullptr) {
                /* 避免重复：若已在 s_open_ports 中记录 frida-server (port=0)，则不再重复添加 frida-server 进程 */
                if (my_strstr(comm, "frida-server") != nullptr) {
                    int j;
                    for (j = 0; j < s_open_port_count; j++)
                        if (get_frida_port_open_at(j) == 0) break;  /* 0 = frida-server+LISTEN 已报告 */
                    if (j < s_open_port_count) continue;  /* 已报告，跳过 */
                }
                /* 新进程，记录详情 */
                snprintf(s_frida_process_details[s_frida_process_count], 256,
                         "Frida process detected: %s (pid %d)", comm, pid);
                s_frida_process_count++;
                LOGD("Frida process: %s (pid %d)", comm, pid);
                break;  /* 每个 pid 只报告一次 */
            }
        }
    }
}

int get_frida_process_detail_count(void) {
    return s_frida_process_count;
}

const char *get_frida_process_detail_at(int index) {
    if (index < 0 || index >= s_frida_process_count) return nullptr;
    return s_frida_process_details[index];
}

int get_frida_port_open_count(void) {
    return s_open_port_count;
}

int get_frida_port_open_at(int index) {
    if (index < 0 || index >= s_open_port_count) return -1;
    return s_open_ports[index];
}

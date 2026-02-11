#include "port_scanner.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>

#define LOG_TAG "AntiFrida"
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

// Frida default ports
static const int FRIDA_PORTS[] = {
    27042, 27043, 27044, 5000, 8080, 0
};

// Last scan result for JNI to build DetectionResult (title/summary/details)
#define MAX_OPEN_PORTS 8
static int s_open_ports[MAX_OPEN_PORTS];
static int s_open_port_count = 0;

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

    for (int i = 0; FRIDA_PORTS[i] != 0 && s_open_port_count < MAX_OPEN_PORTS; i++) {
        if (is_port_open(FRIDA_PORTS[i])) {
            LOGD("Suspicious port detected: %d", FRIDA_PORTS[i]);
            s_open_ports[s_open_port_count++] = FRIDA_PORTS[i];
            found = true;
        }
    }

    /* Check /proc/self/net/tcp via syscalls */
    int fd = my_open("/proc/self/net/tcp", O_RDONLY, 0);
    if (fd >= 0) {
        char buffer[4096];
        ssize_t n = my_read(fd, buffer, sizeof(buffer) - 1);
        my_close(fd);
        if (n > 0) {
            buffer[n] = '\0';
            if (my_strstr(buffer, "699A") || my_strstr(buffer, "699B") || my_strstr(buffer, "699C")) {
                LOGD("Frida port pattern in /proc/net/tcp");
                found = true;
                if (s_open_port_count < MAX_OPEN_PORTS) {
                    int p = 27042;
                    int j;
                    for (j = 0; j < s_open_port_count; j++) if (s_open_ports[j] == p) break;
                    if (j >= s_open_port_count) s_open_ports[s_open_port_count++] = p;
                }
            }
        }
    }
    return found;
}

int get_frida_port_open_count(void) {
    return s_open_port_count;
}

int get_frida_port_open_at(int index) {
    if (index < 0 || index >= s_open_port_count) return -1;
    return s_open_ports[index];
}

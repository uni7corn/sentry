#include "so_integrity.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#ifndef PT_LOAD
#define PT_LOAD 1
#endif
#ifndef PF_X
#define PF_X 1
#endif

#define MAPS_READ_SIZE 262144
#define SCAN_SIZE_MAX 65536
#define CRC_CHUNK_SIZE (64 * 1024)

#if defined(__aarch64__) || defined(__x86_64__)
#define ELF64_ONLY 1
#endif

/* CRC32 表与实现（无 zlib 依赖），用于 libc .text 磁盘 vs 内存对比 */
static uint32_t s_crc32_table[256];
static int s_crc32_table_init;

static void init_crc32_table(void) {
    if (s_crc32_table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        s_crc32_table[i] = c;
    }
    s_crc32_table_init = 1;
}

static uint32_t calc_crc32(uint32_t crc, const unsigned char *data, size_t length) {
    init_crc32_table();
    crc ^= 0xFFFFFFFFu;
    while (length--)
        crc = s_crc32_table[(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

#ifdef ELF64_ONLY
#if defined(__aarch64__)
/*
 * Frida ARM64 Inline Hook 的 8 字节原子特征（误报率极低）：
 * ldr x16, [pc, #8]; br x16  =>  0x58000050 | (0xD61F0200<<32) = 0xD61F020058000050
 * ldr x17, [pc, #8]; br x17  =>  0x58000051 | (0xD61F0220<<32) = 0xD61F022058000051
 * 正常代码的 ldr [pc,#imm] 多为 #16/#24 等，几乎不会出现 #8 的该组合。
 */
static int scan_for_hook_patterns(const void *addr, size_t size) {
    if (size < 8) return 0;
    /* XOM 守卫：匿名可执行段可能只执行不可读，读其字节会 SEGV_ACCERR（issue #2）。 */
    if (!mem_readable(addr, 8)) return 0;
    const uint64_t *code = (const uint64_t *)addr;
    size_t num_qwords = size / 8;

    static const uint64_t FRIDA_PATTERNS[] = {
        0xD61F020058000050ULL,  /* ldr x16, [pc, #8]; br x16 */
        0xD61F022058000051ULL,  /* ldr x17, [pc, #8]; br x17 */
    };

    for (size_t i = 0; i < num_qwords; i++) {
        for (int j = 0; j < 2; j++) {
            if (code[i] == FRIDA_PATTERNS[j]) {
                LOGD("[SO] Frida hook confirmed at offset 0x%zx (pattern=0x%llx)",
                     i * 8, (unsigned long long)code[i]);
                return 1;
            }
        }
    }
    return 0;
}
#else
static int scan_for_hook_patterns(const void *addr, size_t size) {
    (void)addr;
    (void)size;
    return 0;
}
#endif

#endif

/**
 * 仅检查关键函数（open/read/strcmp/strstr）头部 8 字节是否为 Frida 精确特征。
 * @return 0=正常, 1=检测到疑似 Hook
 */
int check_critical_functions(void) {
#if defined(__aarch64__)
    const char *names[] = { "open", "read", "strcmp", "strstr", nullptr };
    const uint64_t p1 = 0xD61F020058000050ULL;
    const uint64_t p2 = 0xD61F022058000051ULL;
    for (int i = 0; names[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, names[i]);
        if (!sym) continue;
        if (!mem_readable(sym, 8)) continue;  /* XOM(.text 只执行不可读)：跳过，防 SEGV */
        uint64_t first8 = *(const uint64_t *)sym;
        if (first8 == p1 || first8 == p2) {
            LOGD("[SO] Critical function %s at %p: Frida hook confirmed", names[i], sym);
            return 1;
        }
    }
#endif
    return 0;
}

/* CRC 检测用：从 dl_iterate_phdr 获取 libc 路径与第一个可执行段信息 */
typedef struct {
    uintptr_t base;
    uintptr_t text_addr;
    size_t text_size;
    off_t text_offset;
    char path[256];
    int found;
} libc_mem_info_t;

static int get_libc_text_info_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info->dlpi_name || my_strstr(info->dlpi_name, "/libc.so") == nullptr)
        return 0;
    libc_mem_info_t *out = (libc_mem_info_t *)data;
    out->base = (uintptr_t)info->dlpi_addr;
    my_strncpy(out->path, info->dlpi_name, sizeof(out->path) - 1);
    out->path[sizeof(out->path) - 1] = '\0';
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        out->text_addr = (uintptr_t)info->dlpi_addr + ph->p_vaddr;
        out->text_size = (size_t)ph->p_memsz;
        out->text_offset = (off_t)ph->p_offset;
        out->found = 1;
        LOGD("[CRC] libc text: addr=%p size=%zu offset=0x%lx", (void *)out->text_addr, out->text_size, (long)out->text_offset);
        return 1;
    }
    return 0;
}

/**
 * CRC 检测：对比 libc.so 磁盘文件与内存中 .text 段（参考 Hunter/DetectFrida）。
 * Android 10+ 可能因 SELinux 无法打开 /apex/.../libc.so 或 XOM 导致读内存崩溃，此时返回 -1，由 GOT/端口等补充。
 * @return 0=正常, 1=检测到篡改, -1=检测失败（未找到/无法打开/读失败）
 */
int check_libc_text_integrity(void) {
#ifdef ELF64_ONLY
    libc_mem_info_t mem_info = {0};
    dl_iterate_phdr(get_libc_text_info_callback, &mem_info);
    if (!mem_info.found) {
        LOGD("[CRC] libc not found in memory");
        return -1;
    }

    /* XOM 守卫：若 libc .text 只执行不可读（部分机型，issue #2），整段 CRC 内存读
     * 会 SEGV_ACCERR 崩溃。探测段首即可判定，整段权限一致。不可读则跳过 CRC（返回
     * -1，由 GOT/端口/匿名段等通道补充）。 */
    if (!mem_readable((const void *)mem_info.text_addr, 8)) {
        LOGD("[CRC] libc .text execute-only (no-read) - skip CRC");
        return -1;
    }

    int used_syscall = 0;
    int fd = open_with_fallback(mem_info.path, O_RDONLY, 0, &used_syscall);
    if (fd < 0) {
        LOGD("[CRC] Cannot open %s", mem_info.path);
        return -1;
    }

    unsigned char *file_buf = (unsigned char *)malloc(CRC_CHUNK_SIZE);
    if (!file_buf) {
        my_close(fd);
        return -1;
    }

    ssize_t sr = my_lseek(fd, mem_info.text_offset, SEEK_SET);
    if (sr < 0 || (off_t)sr != mem_info.text_offset) {
        free(file_buf);
        my_close(fd);
        return -1;
    }

    uint32_t file_crc = 0;
    uint32_t mem_crc = 0;
    size_t remaining = mem_info.text_size;
    size_t offset = 0;

    while (remaining > 0) {
        size_t to_read = remaining > CRC_CHUNK_SIZE ? CRC_CHUNK_SIZE : remaining;
        ssize_t nr = read_with_fallback(fd, file_buf, to_read, used_syscall);
        if (nr != (ssize_t)to_read) {
            LOGD("[CRC] Read failed at offset %zu", offset);
            free(file_buf);
            my_close(fd);
            return -1;
        }
        file_crc = calc_crc32(file_crc, file_buf, to_read);
        mem_crc = calc_crc32(mem_crc, (const unsigned char *)(mem_info.text_addr + offset), to_read);
        remaining -= to_read;
        offset += to_read;
    }

    free(file_buf);
    my_close(fd);

    LOGD("[CRC] file=0x%08x mem=0x%08x", file_crc, mem_crc);
    if (file_crc != mem_crc) {
        LOGD("[CRC] libc.so text section modified");
        return 1;
    }
    return 0;
#else
    return -1;
#endif
}

/*
 * GOT 表完整性：Frida 常通过修改 GOT 重定向 open/read/strcmp 等到 trampoline，
 * 不修改代码段故 8 字节特征检测不到。检查这些符号的解析地址是否仍在 libc 范围内。
 * 不需读磁盘、不需读代码段，适用于 Android 10+ SELinux/XOM 环境。
 */
typedef struct {
    uintptr_t base;
    size_t size;  /* 即 max(p_vaddr + p_memsz)  over PT_LOAD */
} libc_range_t;

static int get_libc_range_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info->dlpi_name || my_strstr(info->dlpi_name, "/libc.so") == nullptr)
        return 0;
    libc_range_t *out = (libc_range_t *)data;
    out->base = (uintptr_t)info->dlpi_addr;
    out->size = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        size_t end = (size_t)(ph->p_vaddr + ph->p_memsz);
        if (end > out->size) out->size = end;
    }
    return 1;  /* 找到 libc，停止迭代 */
}

/**
 * 检测 libc 关键函数（open/read/strcmp）的解析地址是否在 libc 映射范围内；
 * 若被 GOT/PLT 劫持，dlsym 返回的将是 trampoline 地址（通常在 libc 外）。
 * @return 0=正常, 1=检测到 GOT 劫持（函数地址在 libc 外）, -1=未找到 libc
 */
int detect_frida_got_hook(void) {
    libc_range_t range = {0, 0};
    dl_iterate_phdr(get_libc_range_callback, &range);
    if (range.size == 0) {
        LOGD("[SO] GOT check: libc not found");
        return -1;
    }
    uintptr_t base = range.base;
    uintptr_t end = base + range.size;

    const char *names[] = { "open", "read", "strcmp", nullptr };
    for (int i = 0; names[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, names[i]);
        if (!sym) continue;
        uintptr_t addr = (uintptr_t)sym;
        if (addr < base || addr >= end) {
            LOGD("[SO] GOT: %s() at %p outside libc [%lx, %lx)", names[i], sym, (unsigned long)base, (unsigned long)end);
            return 1;
        }
    }
    return 0;
}

/*
 * /proc/self/maps 标准格式：address perms offset dev inode pathname
 * 权限为固定 4 字节（如 r-xp），仅当 perms 含 'x' 时为可执行段。
 * 使用 sscanf 精确定位权限字段，避免 my_strstr("r-xp") 在整行中的误匹配（如 rw-p 行被误判）。
 */
typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[5];      /* r-xp / rwxp 等，4 字节 + null */
    char pathname[256];
} maps_entry_t;

static int parse_maps_line(const char *line, maps_entry_t *entry) {
    memset(entry, 0, sizeof(maps_entry_t));
    /* 至少解析：地址范围、权限；pathname 可选（匿名段无路径） */
    int ret = sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %255s",
                    &entry->start, &entry->end, entry->perms, entry->pathname);
    if (ret < 3) return -1;
    if (ret < 4) entry->pathname[0] = '\0';
    return 0;
}

/* 白名单：合法的匿名/系统可执行段；未命名段按大小容错（ART JIT 通常 4KB~128MB） */
static int is_anon_rx_whitelisted(const char *path, uint64_t start, uint64_t end) {
    uint64_t size = end - start;

    if (!path || !path[0]) {
        if (size >= 4096 && size <= 128ULL * 1024 * 1024) {
            LOGD("[SO] Whitelist unnamed exec segment (size=%llu, likely JIT)", (unsigned long long)size);
            return 1;
        }
        if (size < 65536)
            LOGD("[SO] Small unnamed exec (size=%llu)", (unsigned long long)size);
        return 0;
    }
    if (path[0] == '/') return 1;

    static const char *const whitelist[] = {
        "[vdso]", "[vvar]", "[stack", "[heap]",
        "dalvik-jit", "dalvik-main", "dalvik-",
        "scudo", "linker_alloc", "libc_malloc",
        "jit-cache", "code-cache",
        "[anon:thread signal stack]",
        "[anon:.bss]",
        "[anon:bionic TLS]",
        "[anon:stack_and_tls:",
        "/memfd:",
        nullptr
    };
    for (int i = 0; whitelist[i]; i++) {
        if (my_strstr(path, whitelist[i])) return 1;
    }
    return 0;
}

/**
 * 扫描 maps 中匿名可执行段。使用 sscanf 精确解析权限位，仅当 perms 含 'x' 时才视为可执行，避免误判 rw-p 等。
 * @return 0=未发现, 1=发现可疑段, -1=读取失败
 */
int scan_suspicious_anonymous_rx_memory(void) {
    int used_syscall = 0;
    int fd = open_with_fallback("/proc/self/maps", 0, 0, &used_syscall);
    if (fd < 0) return -1;

    char buf[MAPS_READ_SIZE];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = read_with_fallback(fd, buf + n, sizeof(buf) - 1 - n, used_syscall);
        if (r <= 0) break;
        n += (size_t)r;
    }
    my_close(fd);
    if (n == 0) return -1;
    buf[n] = '\0';

    const char *p = buf;
    while (*p) {
        const char *eol = p;
        while (*eol && *eol != '\n') eol++;

        char line[512];
        size_t line_len = (size_t)(eol - p);
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        memcpy(line, p, line_len);
        line[line_len] = '\0';

        maps_entry_t entry;
        if (parse_maps_line(line, &entry) != 0) {
            p = *eol ? eol + 1 : eol;
            continue;
        }

        /* 仅当权限含 'x'（可执行）时才处理，避免 rw-p 等被误判为 r-xp */
        int has_x = 0;
        for (int i = 0; i < 4 && entry.perms[i]; i++) {
            if (entry.perms[i] == 'x') { has_x = 1; break; }
        }
        if (!has_x) {
            p = *eol ? eol + 1 : eol;
            continue;
        }

        /* 可执行段 */
        int is_anon = (entry.pathname[0] == '\0' || entry.pathname[0] == '[');
        if (is_anon && !is_anon_rx_whitelisted(entry.pathname, entry.start, entry.end)) {
            size_t seg_size = (size_t)(entry.end - entry.start);
            LOGD("[SO] Exec segment: %lx-%lx %s %s", entry.start, entry.end, entry.perms,
                 entry.pathname[0] ? entry.pathname : "(anonymous)");

            if (seg_size <= 65536) {
                if (scan_for_hook_patterns((void *)(uintptr_t)entry.start, seg_size)) {
                    LOGD("[SO] Frida pattern in small exec segment: %.80s", line);
                    return 1;
                }
            } else {
                LOGD("[SO] Large suspicious exec segment: %.120s", line);
                return 1;
            }
        }

        p = *eol ? eol + 1 : eol;
    }
    return 0;
}

/**
 * 快速预检：Frida 默认端口 27042 是否在监听。
 * @return 0=未检测到, 1=检测到
 */
int check_frida_port(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    if (ret == 0) {
        LOGD("[SO] Frida server detected on port 27042");
        return 1;
    }
    return 0;
}

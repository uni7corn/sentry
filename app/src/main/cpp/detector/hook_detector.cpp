#include "hook_detector.h"
#include "memory_scanner.h"
#include "utils/syscall_utils.h"
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#ifndef O_RDONLY
#define O_RDONLY 0
#endif

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#if defined(__aarch64__)
// LR (Link Register) detection: when our detection code is called from an inline hook trampoline,
// LR points to trampoline memory outside our module. Uses syscall to avoid libc hooks.
static int hex_char_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_maps_addr_range(const char *line, uint64_t *out_start, uint64_t *out_end) {
    uint64_t start = 0, end = 0;
    const char *p = line;
    int v;
    while ((v = hex_char_val(*p)) >= 0) {
        start = (start << 4) | (unsigned)v;
        p++;
    }
    if (*p != '-') return false;
    p++;
    while ((v = hex_char_val(*p)) >= 0) {
        end = (end << 4) | (unsigned)v;
        p++;
    }
    *out_start = start;
    *out_end = end;
    return true;
}

// Find the maps entry containing addr; uses syscall (my_open/my_read) to bypass libc.
static bool get_module_bounds(void *addr_in_module, uint64_t *out_start, uint64_t *out_end) {
    static uint64_t cached_start = 0, cached_end = 0;
    static int cached = 0;
    uint64_t addr = (uint64_t)(uintptr_t)addr_in_module;

    if (cached && addr >= cached_start && addr < cached_end) {
        *out_start = cached_start;
        *out_end = cached_end;
        return true;
    }

    int fd = my_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    char buf[4096];
    ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
    my_close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    const char *p = buf;
    while (*p) {
        const char *eol = p;
        while (*eol && *eol != '\n') eol++;
        if (eol > p) {
            uint64_t start, end;
            if (parse_maps_addr_range(p, &start, &end) && addr >= start && addr < end) {
                cached_start = start;
                cached_end = end;
                cached = 1;
                *out_start = start;
                *out_end = end;
                return true;
            }
        }
        p = *eol ? eol + 1 : eol;
    }
    return false;
}

// Returns true if lr (return address of our caller) is outside our module -> likely inline hook.
static bool is_lr_suspicious(uint64_t lr) {
    if (lr == 0) return false;

    uint64_t start, end;
    if (!get_module_bounds((void *)is_lr_suspicious, &start, &end)) {
        return false;
    }

    if (lr < start || lr >= end) {
        LOGD("LR (0x%llx) outside module [0x%llx-0x%llx] - inline hook trampoline suspected",
             (unsigned long long)lr, (unsigned long long)start, (unsigned long long)end);
        return true;
    }
    return false;
}
#endif

// Check for inline hooks by verifying function prologue (Frida Interceptor 典型为 LDR+BR 序言)
static bool check_function_hooked(void *func_addr) {
    if (func_addr == nullptr) {
        return false;
    }

    unsigned char *bytes = (unsigned char *)func_addr;

#if defined(__aarch64__)
    // ARM64: Frida/Dobby 常见 LDR X16/X17, [PC, #0]; BR X16/X17（长跳转序言）
    // LDR X16, [PC, #0]  little-endian: 58 00 00 50
    // BR X16              little-endian: 00 02 1F D6
    // BR X17              little-endian: 20 02 1F D6
    if (bytes[0] == 0x58 && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x50) {
        if ((bytes[4] == 0x00 && bytes[5] == 0x02 && bytes[6] == 0x1F && bytes[7] == 0xD6) ||
            (bytes[4] == 0x20 && bytes[5] == 0x02 && bytes[6] == 0x1F && bytes[7] == 0xD6)) {
            LOGD("Potential inline hook detected (ARM64 LDR+BR trampoline)");
            return true;
        }
    }
    if (bytes[0] == 0x59 && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x50) {
        if ((bytes[4] == 0x20 && bytes[5] == 0x02 && bytes[6] == 0x1F && bytes[7] == 0xD6) ||
            (bytes[4] == 0x00 && bytes[5] == 0x02 && bytes[6] == 0x1F && bytes[7] == 0xD6)) {
            LOGD("Potential inline hook detected (ARM64 LDR+BR trampoline)");
            return true;
        }
    }
    // ARM64 无条件 B 跳转（0x14 为 B 的 opcode 高 bits）
    if ((bytes[3] & 0xFC) == 0x14 && (bytes[0] | bytes[1] | bytes[2]) != 0) {
        LOGD("Potential inline hook detected (ARM64 branch)");
        return true;
    }
#elif defined(__arm__)
    // ARM32: B (unconditional branch) 0xEA
    if (bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0xEA) {
        LOGD("Potential inline hook detected (ARM32 branch)");
        return true;
    }
    if (bytes[3] == 0xE5 && bytes[2] == 0x9F && bytes[1] == 0xF0) {
        LOGD("Potential inline hook detected (LDR PC)");
        return true;
    }
#else
    (void)bytes;
#endif
    return false;
}

bool check_inline_hooks(void) {
    bool hooked = false;

    // Check common hooked functions
    void *malloc_addr = dlsym(RTLD_DEFAULT, "malloc");
    void *free_addr = dlsym(RTLD_DEFAULT, "free");
    void *open_addr = dlsym(RTLD_DEFAULT, "open");
    void *read_addr = dlsym(RTLD_DEFAULT, "read");
    void *write_addr = dlsym(RTLD_DEFAULT, "write");
    void *connect_addr = dlsym(RTLD_DEFAULT, "connect");
    void *socket_addr = dlsym(RTLD_DEFAULT, "socket");

    if (check_function_hooked(malloc_addr)) {
        LOGD("malloc appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(free_addr)) {
        LOGD("free appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(open_addr)) {
        LOGD("open appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(read_addr)) {
        LOGD("read appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(write_addr)) {
        LOGD("write appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(connect_addr)) {
        LOGD("connect appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(socket_addr)) {
        LOGD("socket appears to be hooked");
        hooked = true;
    }

    return hooked;
}

/* GOT 指针逃逸检测：dlsym 返回的地址若落在可疑匿名 r-x 段，则疑为 Frida trampoline */
static bool check_got_points_to_anon_trampoline(void) {
    const char *syms[] = { "malloc", "free", "open", "read", "write", "connect", "socket", nullptr };
    for (int i = 0; syms[i]; i++) {
        void *addr = dlsym(RTLD_DEFAULT, syms[i]);
        if (!addr) continue;
        uint64_t u = (uint64_t)(uintptr_t)addr;
        if (u == 0 || u >= 0x0000008000000000ULL) continue;  /* 跳过明显非法指针 */
        if (is_address_in_suspicious_anon_exec(u)) {
            LOGD("PLT/GOT: %s (0x%llx) points to suspicious anonymous r-x (possible trampoline)",
                 syms[i], (unsigned long long)u);
            return true;
        }
    }
    return false;
}

bool check_plt_hooks(void) {
    return check_got_points_to_anon_trampoline();
}

/* 使用 syscall 打开/读取 libc，避免 libc 的 open/close 被 hook 后误判 */
bool check_library_integrity(void) {
    int fd = my_open("/system/lib64/libc.so", O_RDONLY, 0);
    if (fd < 0) {
        fd = my_open("/system/lib/libc.so", O_RDONLY, 0);
    }
    if (fd < 0) {
        LOGD("Cannot open libc (syscall) - possible tampering or path");
        return true;
    }
    my_close(fd);
    return false;
}

bool detect_hooks(void) {
    bool hooked = false;

#if defined(__aarch64__)
    {
        uint64_t lr;
        __asm__ __volatile__("mov %0, x30" : "=r"(lr));
        if (is_lr_suspicious(lr)) {
            return true;
        }
    }
#endif

    if (check_inline_hooks()) {
        hooked = true;
    }

    if (check_plt_hooks()) {
        hooked = true;
    }

    if (check_library_integrity()) {
        hooked = true;
    }

    return hooked;
}

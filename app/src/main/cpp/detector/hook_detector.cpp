#include "hook_detector.h"
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

// Check for inline hooks by verifying function prologue
static bool check_function_hooked(void *func_addr) {
    if (func_addr == nullptr) {
        return false;
    }

    unsigned char *bytes = (unsigned char *)func_addr;

    // Check for ARM/ARM64 hook patterns
    // Common hook prologues:
    // - Branch to hook (B/BX/BL)
    // - LDR PC, [PC, #offset]
    // - MOV PC, Rm

    // Check for ARM64 branch
    if (bytes[0] == 0x00 || bytes[0] == 0x01 || bytes[0] == 0x02 || bytes[0] == 0x03) {
        // Potential branch instruction
        if ((bytes[3] & 0xFC) == 0x14) {
            LOGD("Potential inline hook detected (ARM64 branch)");
            return true;
        }
    }

    // Check for ARM32 hook patterns
    if (bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0xEA) {
        // B (unconditional branch)
        LOGD("Potential inline hook detected (ARM32 branch)");
        return true;
    }

    // Check for LDR PC pattern
    if (bytes[3] == 0xE5 && bytes[2] == 0x9F && bytes[1] == 0xF0) {
        LOGD("Potential inline hook detected (LDR PC)");
        return true;
    }

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

bool check_plt_hooks(void) {
    // Check PLT/GOT for suspicious entries
    // This requires parsing ELF headers which is complex
    // For now, we'll use a simplified check

    Dl_info info;
    void *malloc_addr = dlsym(RTLD_DEFAULT, "malloc");

    if (malloc_addr && dladdr(malloc_addr, &info)) {
        LOGD("malloc found in: %s", info.dli_fname ? info.dli_fname : "unknown");

        // If malloc is not in libc, it might be hooked
        if (info.dli_fname && strstr(info.dli_fname, "libc.so") == nullptr &&
            strstr(info.dli_fname, "libc++.so") == nullptr) {
            LOGD("malloc not in libc - possible PLT hook");
            return true;
        }
    }

    return false;
}

bool check_library_integrity(void) {
    // Check if critical libraries have been tampered with
    // This involves comparing memory sections with on-disk files

    // For now, just check if libc can be opened normally
    int fd = open("/system/lib64/libc.so", O_RDONLY);
    if (fd < 0) {
        fd = open("/system/lib/libc.so", O_RDONLY);
    }

    if (fd < 0) {
        LOGD("Cannot open libc - possible tampering");
        return true;
    }

    close(fd);
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

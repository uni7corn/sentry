#include "memory_scanner.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Frida + LSPosed + Xposed + Riru + Zygisk + JS 引擎 memory signatures (use syscall to bypass libc hook)
// 含 QuickJS/frida-java-bridge/linjector（OWASP MASTG：Frida 当前用 QuickJS，frida-java-bridge 等）
static const char *FRIDA_SIGNATURES[] = {
    "frida",
    "FRIDA",
    "gum-js",
    "gumjs",
    "gthread",
    "gobject",
    "gmain",
    "gdbus",
    "frida-agent",
    "frida-gadget",
    "frida-server",
    "frida-java-bridge",
    "linjector",
    "QuickJS",
    "quickjs",
    "libquickjs",
    "liblspd.so",
    "libriru.so",
    "libriruloader.so",
    /* Xposed / LSPosed / EdXposed */
    "libxposed",
    "xposed_art",
    "xposed_bridge",
    "XposedBridge",
    "XposedHelpers",
    "xposed.installer",
    "XposedBridge.jar",
    "de.robv.android.xposed",
    "org.lsposed",
    /* Zygisk LSPosed：maps 中 /data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so */
    "zygisk_lsposed",
    "zygisk",
    nullptr
};

#define MAX_MEMORY_FINDINGS 16
static char s_findings[MAX_MEMORY_FINDINGS][256];
static int s_finding_count = 0;

/* 匿名可执行内存：LSPosed 隐藏 so 时仍保留可执行权限；默认 128KB 降低 JIT 误报，高级模式 4KB */
#define ANON_EXEC_SIZE_THRESHOLD_DEFAULT (128 * 1024)
#define ANON_EXEC_SIZE_THRESHOLD_ADVANCED (4 * 1024)
#define MAX_ANON_EXEC_FINDINGS 2
#define TRAMPOLINE_SCAN_SIZE (64 * 1024)   /* 每段最多扫描 64KB */
#define TRAMPOLINE_MIN_MATCHES 2            /* 至少 2 处匹配才报，降低误报 */

/* ARM64 Frida 典型 Trampoline：LDR X16/X17,[PC]; BR X16/X17 */
static int count_trampoline_patterns(const unsigned char *buf, size_t len) {
    int count = 0;
    if (len < 8) return 0;
    for (size_t i = 0; i + 8 <= len; i += 4) {  /* ARM64 4 字节对齐 */
        if ((buf[i] == 0x58 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x50) ||
            (buf[i] == 0x59 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x50)) {
            if ((buf[i+4] == 0x00 && buf[i+5] == 0x02 && buf[i+6] == 0x1F && buf[i+7] == 0xD6) ||
                (buf[i+4] == 0x20 && buf[i+5] == 0x02 && buf[i+6] == 0x1F && buf[i+7] == 0xD6)) {
                count++;
            }
        }
    }
    return count;
}

/* 安全读取匿名段前 N 字节，检测 Trampoline 特征；返回匹配次数 */
static int scan_region_for_trampoline(unsigned long start, unsigned long end) {
    size_t to_read = (size_t)(end - start);
    if (to_read > TRAMPOLINE_SCAN_SIZE) to_read = TRAMPOLINE_SCAN_SIZE;
    if (to_read < 16) return 0;

    unsigned char *ptr = (unsigned char *)(uintptr_t)start;
    /* XOM 守卫：匿名可执行段可能只执行不可读，读其字节会 SEGV_ACCERR（issue #2）。 */
    if (!mem_readable(ptr, 16)) return 0;
    return count_trampoline_patterns(ptr, to_read);
}

static bool has_exec_perm(const char *perms) {
    if (!perms) return false;
    for (int i = 0; i < 4 && perms[i]; i++) {
        if (perms[i] == 'x') return true;
    }
    return false;
}

/* 已知良性的匿名段：排除后避免误报（JIT、内存分配器等） */
static bool is_anon_path_suspicious(const char *path) {
    if (!path || !path[0]) return true;
    if (path[0] == '/') return false;  /* 文件路径，非匿名 */
    if (path[0] == '[') {
        /* 精确匹配的良性段 */
        const char *skip_exact[] = {
            "[vdso]", "[vvar]", "[stack]", "[heap]",
            "[anon:vdso]", "[anon:vvar]",
            nullptr
        };
        for (int i = 0; skip_exact[i]; i++) {
            const char *s = path, *t = skip_exact[i];
            while (*s && *t && (*s == *t || (*s >= 'A' && *s <= 'Z' && *s + 32 == *t))) s++, t++;
            if (!*t && (*s == ']' || *s == '\0')) return false;  /* 已知良性 */
        }
        /* 前缀匹配：dalvik-jit-code-cache（ART JIT）、scudo（分配器）、linker_alloc、libc_malloc */
        if (my_strstr(path, "dalvik-jit") != nullptr) return false;
        if (my_strstr(path, "scudo") != nullptr) return false;
        if (my_strstr(path, "linker_alloc") != nullptr) return false;
        if (my_strstr(path, "libc_malloc") != nullptr) return false;
        if (my_strstr(path, "jit-cache") != nullptr) return false;  /* 其他 JIT 变体 */
        return true;  /* [anon:xxx] 未在白名单，视为可疑 */
    }
    return true;  /* 其他无名 */
}

static void check_anon_exec_memory(const char *line, char (*findings)[256], int max_findings,
                                   int *count, int *anon_count, size_t size_threshold) {
    if (*anon_count >= MAX_ANON_EXEC_FINDINGS) return;
    unsigned long start = 0, end = 0;
    char perms[8] = {0};
    char path[384] = {0};
    if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %383s", &start, &end, perms, path) < 3)
        return;
    size_t size = end - start;
    if (size < size_threshold || !has_exec_perm(perms) || !is_anon_path_suspicious(path))
        return;
    if (*count < max_findings) {
        int tramp = scan_region_for_trampoline(start, end);
        if (tramp >= TRAMPOLINE_MIN_MATCHES) {
            snprintf(findings[*count], 256, "Anonymous r-x with trampoline-like code: %lx-%lx (%d matches)",
                     start, end, tramp);
        } else {
            snprintf(findings[*count], 256, "Anonymous executable memory: %lx-%lx (size: %zu KB)",
                     start, end, size / 1024);
        }
        (*count)++;
        (*anon_count)++;
    }
}

int get_memory_signature_details(char (*details)[256], int max_details) {
    return get_memory_signature_details_ex(details, max_details, false);
}

int get_memory_signature_details_ex(char (*details)[256], int max_details, int advanced_checks) {
    LOGD("[Memory] scan start advanced=%d", advanced_checks ? 1 : 0);
    s_finding_count = 0;
    int anon_exec_count = 0;
    size_t anon_threshold = advanced_checks ? ANON_EXEC_SIZE_THRESHOLD_ADVANCED : ANON_EXEC_SIZE_THRESHOLD_DEFAULT;
    int used_syscall = 0;
    int fd = open_with_fallback("/proc/self/maps", 0, 0, &used_syscall);  /* 先 syscall 再 libc，兼容多系统 */
    if (fd < 0) {
        LOGD("Failed to open /proc/self/maps (syscall and libc fallback)");
        return -1;  /* 无法读取 maps 时返回 -1，由 JNI 显示 Check skipped */
    }

    char buffer[4096];
    ssize_t bytes_read;
    char line[512];
    int line_pos = 0;

    while ((bytes_read = read_with_fallback(fd, buffer, sizeof(buffer), used_syscall)) > 0) {
        for (ssize_t i = 0; i < bytes_read && s_finding_count < max_details; i++) {
            if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';
                /* Logcat: 扫描 maps 时打印每行内容 */
                // if (line[0] != '\0') {
                //     LOGD("[maps] %s", line);
                // }

                for (int j = 0; FRIDA_SIGNATURES[j] != nullptr && s_finding_count < max_details; j++) {
                    if (my_strcasestr(line, FRIDA_SIGNATURES[j]) != nullptr) {
                        LOGD("Frida signature found in maps: %s (matches: %s)",
                             line, FRIDA_SIGNATURES[j]);
                        snprintf(s_findings[s_finding_count], 256,
                                 "Found '%s' in: %s", FRIDA_SIGNATURES[j], line);
                        s_finding_count++;
                        break;
                    }
                }
                /* 匿名可执行内存：LSPosed 隐藏 so 时仍保留可执行权限 */
                check_anon_exec_memory(line, s_findings, MAX_MEMORY_FINDINGS, &s_finding_count, &anon_exec_count, anon_threshold);

                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
    }

    my_close(fd);
    LOGD("[Memory] scan done: findings=%d", s_finding_count);
    if (details) {
        for (int i = 0; i < s_finding_count && i < max_details; i++) {
            snprintf(details[i], 256, "%s", s_findings[i]);
        }
    }
    return s_finding_count;
}

bool detect_frida_memory_signatures(void) {
    char dummy[1][256];
    return get_memory_signature_details(dummy, 1) > 0;
}

bool scan_maps_for_frida(void) {
    return detect_frida_memory_signatures();
}

/* 判断 addr 是否落在可疑匿名可执行段（排除 dalvik-jit/scudo 等良性段） */
bool is_address_in_suspicious_anon_exec(uint64_t addr) {
    int used_syscall = 0;
    int fd = open_with_fallback("/proc/self/maps", 0, 0, &used_syscall);
    if (fd < 0) return false;

    char buf[262144];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = read_with_fallback(fd, buf + n, sizeof(buf) - 1 - n, used_syscall);
        if (r <= 0) break;
        n += (size_t)r;
    }
    my_close(fd);
    if (n == 0) return false;
    buf[n] = '\0';

    const char *p = buf;
    while (*p) {
        const char *eol = p;
        while (*eol && *eol != '\n') eol++;

        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char path[384] = {0};
        if (sscanf(p, "%lx-%lx %4s %*s %*s %*s %383s", &start, &end, perms, path) >= 3) {
            if (has_exec_perm(perms) && is_anon_path_suspicious(path)) {
                if (addr >= (uint64_t)start && addr < (uint64_t)end)
                    return true;
            }
        }
        p = *eol ? eol + 1 : eol;
    }
    return false;
}

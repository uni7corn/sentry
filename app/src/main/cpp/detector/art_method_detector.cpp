#include "art_method_detector.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* ART 中 jmethodID 即 ArtMethod*；entry_point 偏移因版本而异，arm64 常见 48/56，部分版本 64 */
#define ART_METHOD_ENTRY_OFFSET_1  48
#define ART_METHOD_ENTRY_OFFSET_2  56
#define ART_METHOD_ENTRY_OFFSET_3  64

#define MAX_MAPS_RANGES 256
static struct { uint64_t start; uint64_t end; } s_exec_ranges[MAX_MAPS_RANGES];
static int s_exec_count;

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void parse_maps_exec_ranges(void) {
    s_exec_count = 0;
    int used_syscall = 0;
    int fd = open_with_fallback("/proc/self/maps", 0, 0, &used_syscall);  /* 先 syscall 再 libc，兼容多系统 */
    if (fd < 0) {
        LOGD("[ArtMethod] maps open failed (syscall and libc fallback)");
        return;
    }

    char buf[262144];  /* 256KB，与 SO 一致 */
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = read_with_fallback(fd, buf + n, sizeof(buf) - 1 - n, used_syscall);
        if (r <= 0) break;
        n += (size_t)r;
    }
    my_close(fd);
    if (n == 0) return;
    buf[n] = '\0';
    LOGD("[ArtMethod] maps read %zu bytes", n);

    const char *p = buf;
    while (*p && s_exec_count < MAX_MAPS_RANGES) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        const char *path = nullptr;
        while (*p && *p != '-') {
            int v = hex_val(*p);
            if (v >= 0) start = (start << 4) | (unsigned)v;
            p++;
        }
        if (*p != '-') { p = my_strstr(p, "\n"); p = p ? p + 1 : buf + n; continue; }
        p++;
        while (*p && *p != ' ') {
            int v = hex_val(*p);
            if (v >= 0) end = (end << 4) | (unsigned)v;
            p++;
        }
        while (*p == ' ') p++;
        for (int i = 0; i < 4 && *p && *p != ' '; i++) { perms[i] = *p; p++; }
        while (*p && *p != '\n') {
            while (*p == ' ') p++;
            if (*p && *p != '\n') path = p;
            while (*p && *p != ' ' && *p != '\n') p++;
        }
        if (*p == '\n') p++;

        int exec = 0;
        for (int j = 0; j < 4 && perms[j]; j++) if (perms[j] == 'x') { exec = 1; break; }
        if (exec) {  /* 纳入所有可执行映射，减少误报（oat/jit/apex 等） */
            s_exec_ranges[s_exec_count].start = start;
            s_exec_ranges[s_exec_count].end = end;
            s_exec_count++;
        }
    }
    LOGD("[ArtMethod] parsed %d exec ranges", s_exec_count);
    /* 调试：打印前 8 与后 4 个 exec 区间 */
    for (int i = 0; i < s_exec_count && i < 8; i++)
        LOGD("[ArtMethod] range[%d] 0x%llx-0x%llx", i, (unsigned long long)s_exec_ranges[i].start, (unsigned long long)s_exec_ranges[i].end);
    if (s_exec_count > 12)
        for (int i = s_exec_count - 4; i < s_exec_count; i++)
            LOGD("[ArtMethod] range[%d] 0x%llx-0x%llx", i, (unsigned long long)s_exec_ranges[i].start, (unsigned long long)s_exec_ranges[i].end);
}

static int in_exec_range(uint64_t addr) {
    for (int i = 0; i < s_exec_count; i++) {
        if (addr >= s_exec_ranges[i].start && addr < s_exec_ranges[i].end)
            return 1;
    }
    return 0;
}

/* 调试：当 addr 不在任何区间时，打印最近的区间（start <= addr 的最大 start） */
static void log_nearest_range(uint64_t addr) {
    uint64_t best_start = 0;
    uint64_t best_end = 0;
    int found = 0;
    for (int i = 0; i < s_exec_count; i++) {
        if (s_exec_ranges[i].start <= addr && s_exec_ranges[i].end > addr) return; /* 在范围内，无需调试 */
        if (s_exec_ranges[i].start <= addr && s_exec_ranges[i].start > best_start) {
            best_start = s_exec_ranges[i].start;
            best_end = s_exec_ranges[i].end;
            found = 1;
        }
    }
    if (found)
        LOGD("[ArtMethod] addr 0x%llx outside: nearest range 0x%llx-0x%llx (addr after end)", (unsigned long long)addr, (unsigned long long)best_start, (unsigned long long)best_end);
    else
        LOGD("[ArtMethod] addr 0x%llx outside: no range with start<=addr", (unsigned long long)addr);
}

int art_method_check_entry_points(JNIEnv *env, jclass targetClass, char *detailBuf, size_t detailSize) {
    if (!env || !targetClass || !detailBuf || detailSize == 0) return -1;

    jmethodID onCreate = env->GetMethodID(targetClass, "onCreate", "(Landroid/os/Bundle;)V");
    if (!onCreate) {
        LOGD("[ArtMethod] GetMethodID(onCreate) failed");
        if (detailSize > 0) my_strcpy(detailBuf, "Check skipped (Activity.onCreate not found)");
        return -1;
    }

    void *artMethod = (void *)onCreate;
    uintptr_t e1 = *(uintptr_t *)((char *)artMethod + ART_METHOD_ENTRY_OFFSET_1);
    uintptr_t e2 = *(uintptr_t *)((char *)artMethod + ART_METHOD_ENTRY_OFFSET_2);
    uintptr_t e3 = *(uintptr_t *)((char *)artMethod + ART_METHOD_ENTRY_OFFSET_3);

    parse_maps_exec_ranges();
    if (s_exec_count == 0) {
        LOGD("[ArtMethod] No exec ranges (maps unreadable or empty)");
        if (detailSize > 0) my_strcpy(detailBuf, "Check skipped (could not read /proc/self/maps)");
        return -1;
    }

    /* 排除明显非指针的值（如 packed/flags），arm64 用户空间通常 < 0x800000000000 */
    int valid1 = e1 && e1 < 0x0000008000000000ULL;
    int valid2 = e2 && e2 < 0x0000008000000000ULL;
    int valid3 = e3 && e3 < 0x0000008000000000ULL;

    int in1 = valid1 ? in_exec_range(e1) : 1;
    int in2 = valid2 ? in_exec_range(e2) : 1;
    int in3 = valid3 ? in_exec_range(e3) : 1;

    /* 任一有效 entry 在合法范围内即视为通过（不同 ART 版本用不同 offset） */
    int any_in = (valid1 && in1) || (valid2 && in2) || (valid3 && in3);
    int any_valid = valid1 || valid2 || valid3;

    LOGD("[ArtMethod] entry@48=0x%zx v=%d in=%d, @56=0x%zx v=%d in=%d, @64=0x%zx v=%d in=%d, any_in=%d",
         (size_t)e1, valid1, in1, (size_t)e2, valid2, in2, (size_t)e3, valid3, in3, any_in);

    if (valid1 && !in1) log_nearest_range(e1);
    if (valid2 && !in2) log_nearest_range(e2);

    if (any_valid && !any_in) {
        LOGD("[ArtMethod] FAIL: all valid entries outside exec ranges");
        if (detailSize > 60)
            my_strcpy(detailBuf, "onCreate entry point outside libart/oat (possible trampoline)");
        return 1;
    }
    LOGD("[ArtMethod] PASS: all entry points in valid ranges");
    if (detailSize > 0)
        my_strcpy(detailBuf, "Entry points within libart/oat/jit/apex ranges");
    return 0;
}

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
typedef struct {
    uint64_t start;
    uint64_t end;
} exec_range_t;
static exec_range_t s_exec_ranges[MAX_MAPS_RANGES];
static int s_exec_count;

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 解析单行 maps 文本（不含换行），写入 entry。返回 1=可执行段、0=非可执行、-1=parse 失败 */
static int parse_one_maps_line(const char *line, exec_range_t *entry) {
    uint64_t start = 0, end = 0;
    char perms[8] = {0};
    const char *p = line;
    while (*p && *p != '-') {
        int v = hex_val(*p);
        if (v < 0) return -1;
        start = (start << 4) | (unsigned)v;
        p++;
    }
    if (*p != '-') return -1;
    p++;
    while (*p && *p != ' ') {
        int v = hex_val(*p);
        if (v < 0) return -1;
        end = (end << 4) | (unsigned)v;
        p++;
    }
    while (*p == ' ') p++;
    for (int i = 0; i < 4 && *p && *p != ' '; i++) { perms[i] = *p; p++; }
    int exec = 0;
    for (int j = 0; j < 4 && perms[j]; j++) if (perms[j] == 'x') { exec = 1; break; }
    entry->start = start;
    entry->end = end;
    return exec ? 1 : 0;
}

/* 历史问题：旧实现用 256KB 一次性缓冲。一个常见 App 进程的 /proc/self/maps 现在
 * 经常 > 1MB（apex、art、所有 NDK 库、JIT 段、各种 anon），超出部分被截断 →
 * 落在后段的合法 entry_point 会被判为 "outside libart" 产生误报。
 *
 * 改为分块读 + 流式行解析：内存用量恒定（4KB IO + 512 字节行缓冲），不再受
 * maps 总长限制，可执行段数仍受 MAX_MAPS_RANGES（256）兜底以防 OOB。 */
static void parse_maps_exec_ranges(void) {
    s_exec_count = 0;
    int used_syscall = 0;
    int fd = open_with_fallback("/proc/self/maps", 0, 0, &used_syscall);
    if (fd < 0) {
        LOGD("[ArtMethod] maps open failed (syscall and libc fallback)");
        return;
    }

    char io_buf[4096];
    char line_buf[512];
    size_t line_pos = 0;
    size_t total_bytes = 0;
    ssize_t rd;

    while ((rd = read_with_fallback(fd, io_buf, sizeof(io_buf), used_syscall)) > 0
           && s_exec_count < MAX_MAPS_RANGES) {
        total_bytes += (size_t)rd;
        for (ssize_t i = 0; i < rd && s_exec_count < MAX_MAPS_RANGES; i++) {
            char c = io_buf[i];
            if (c == '\n' || line_pos >= sizeof(line_buf) - 1) {
                line_buf[line_pos] = '\0';
                if (line_pos > 0) {
                    exec_range_t e;
                    if (parse_one_maps_line(line_buf, &e) == 1) {
                        s_exec_ranges[s_exec_count].start = e.start;
                        s_exec_ranges[s_exec_count].end = e.end;
                        s_exec_count++;
                    }
                }
                line_pos = 0;
                if (c != '\n') {
                    /* 行被截断（极长 pathname），跳过直到换行 */
                    while (i < rd && io_buf[i] != '\n') i++;
                }
            } else {
                line_buf[line_pos++] = c;
            }
        }
    }
    /* 文件末尾无换行的最后一行 */
    if (line_pos > 0 && s_exec_count < MAX_MAPS_RANGES) {
        line_buf[line_pos] = '\0';
        exec_range_t e;
        if (parse_one_maps_line(line_buf, &e) == 1) {
            s_exec_ranges[s_exec_count].start = e.start;
            s_exec_ranges[s_exec_count].end = e.end;
            s_exec_count++;
        }
    }
    my_close(fd);
    LOGD("[ArtMethod] streamed %zu bytes from maps, parsed %d exec ranges",
         total_bytes, s_exec_count);
    /* 调试：打印前 8 与后 4 个 exec 区间 */
    for (int i = 0; i < s_exec_count && i < 8; i++)
        LOGD("[ArtMethod] range[%d] 0x%llx-0x%llx", i,
             (unsigned long long)s_exec_ranges[i].start,
             (unsigned long long)s_exec_ranges[i].end);
    if (s_exec_count > 12)
        for (int i = s_exec_count - 4; i < s_exec_count; i++)
            LOGD("[ArtMethod] range[%d] 0x%llx-0x%llx", i,
                 (unsigned long long)s_exec_ranges[i].start,
                 (unsigned long long)s_exec_ranges[i].end);
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

#include "class_linker_scan.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

/**
 * ClassLinker class_loaders_ 链表节点计数（ART 内存扫）。
 *
 * 思路来源：bbs 上一篇基于 ART 内存特征的 LSPosed 检测方案。核心是 LSPosed
 * 必须把模块 ClassLoader 挂在 ClassLinker::class_loaders_ 链上（否则 GC 回收），
 * 这是 GC 模型决定的"硬约束"，比 API 层的所有特征都难撒谎。
 *
 * 算法：
 *   1. env->GetJavaVM() → JavaVMExt 指针
 *   2. JavaVMExt 内 +sizeof(void*) 处取 Runtime* （vtable@0, runtime_@8）
 *   3. 扫 Runtime 内 [0, 0x500) 找 ClassLinker*，特征 A：第一个 8 字节（vtable）
 *      落在 libart.so 内存区间
 *   4. 在 ClassLinker 内扫 [0, 0x500) 找 std::list 头，特征 B：next->prev==head
 *      且 prev->next==head（双向闭环），特征 C：节点数 ≥ 2
 *   5. 命中后缓存两个偏移，后续直接读
 *
 * 误报/失败语义：
 *   - 返回 -1：扫描失败（任何环节失败），上层视作"无信号"，不扣分不警示
 *   - 返回 ≥0：可信计数；阈值判定在 Java 侧
 *
 * 已知局限（文档要写清）：
 *   - JavaVMExt 内 Runtime* 偏移依赖 ART 私有布局，每个大版本可能变。当前在
 *     Android 7-14 验证稳定，15/16 上若失败则返回 -1（fail-safe）
 *   - 0x500 暴力枚举范围有可能误命中其他双向链表（如 dex_caches_）。命中后
 *     的"节点数 ≥ 2 且 ≤ 256"约束 + libart vtable 校验可以挡掉绝大多数误命中
 *   - mincore 仅校验页 mapped，不校验内容语义。攻击者可以 Hook mincore，但
 *     Hook mincore 容易导致系统不稳定，所以实践中很少见
 *   - 攻击者可以直接 Hook 本 JNI 函数返回伪造值——这跟其他所有 native 检测
 *     一样面临，不是本检测特有的弱点
 */

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

namespace {

struct ListNode {
    ListNode *next;
    ListNode *prev;
};

/* 去指针标签（TBI / Android heap pointer tagging）：arm64 上层 app 的堆指针
 * 顶字节常带 0xb4 等 tag，硬件解引用时忽略（Top-Byte-Ignore），但裸算术比较
 * 会被这些高位污染。所有"拿来跟 maps 区间比较 / 互相比较"的指针都先规范化。
 * 清掉高 8 位（bits 56-63）即可覆盖 TBI tag 与 Android 的 0xb4 堆标签。 */
static inline uintptr_t canon(const void *p) {
    return (uintptr_t)p & 0x00FFFFFFFFFFFFFFULL;
}

/* 缓存：首次扫描成功后存下三个偏移，后续直接走快速路径。
 * g_vm_runtime_off：从 JavaVM 指针到 Runtime* 的字节偏移（见下方说明）。 */
static int g_vm_runtime_off = -1;
static int g_cl_offset = -1;
static int g_list_offset = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* 快速排除明显非法的指针：null / 太小（前 64KB 为 SELinux 保护区域）/ 太大
 * （arm64 用户态上限 0x0000_8000_0000_0000）/ 未对齐。 */
static inline bool plausible_pointer(uintptr_t p) {
    return p >= 0x10000ULL
        && p < 0x0000800000000000ULL
        && (p & (sizeof(void *) - 1)) == 0;
}

/* 可读区间表：解析 /proc/self/maps 收集所有带 'r' 权限的映射段。
 *
 * 为什么不用 mincore：实测 Android 16 上 mincore 对 app 进程会失败（返回非 0
 * 或被 seccomp 限制），导致所有 is_addr_readable 判否，整个扫描提前夭折。
 * 改为以 maps 的实际可读区间判定地址有效性——syscall 直读，抗 hook，且只需
 * 一次解析，比每次 mincore 系统调用更快。 */
#define MAX_READABLE_RANGES 8192   /* 现代 App maps 段数可达数千，需足够大 */
static uintptr_t g_rng_lo[MAX_READABLE_RANGES];
static uintptr_t g_rng_hi[MAX_READABLE_RANGES];
static int g_rng_count = 0;

/* 解析 /proc/self/maps，填充可读区间表（仅 perms[0]=='r' 的段）。每次扫描前刷新。 */
static void refresh_readable_ranges(void) {
    g_rng_count = 0;
    int fd = my_open("/proc/self/maps", 0, 0);
    if (fd < 0) return;
    char io_buf[8192];
    char line[512];
    size_t lp = 0;
    ssize_t rd;
    while ((rd = my_read(fd, io_buf, sizeof(io_buf))) > 0) {
        for (ssize_t i = 0; i < rd; i++) {
            char c = io_buf[i];
            if (c == '\n' || lp >= sizeof(line) - 1) {
                line[lp] = '\0';
                lp = 0;
                unsigned long s = 0, e = 0;
                char perms[8] = {0};
                /* 格式: "<lo>-<hi> rwxp ..." */
                if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) == 3
                        && perms[0] == 'r' && g_rng_count < MAX_READABLE_RANGES) {
                    g_rng_lo[g_rng_count] = (uintptr_t)s;
                    g_rng_hi[g_rng_count] = (uintptr_t)e;
                    g_rng_count++;
                }
                if (c != '\n') {
                    while (i < rd && io_buf[i] != '\n') i++;
                }
            } else {
                line[lp++] = c;
            }
        }
    }
    my_close(fd);
}

/* 地址是否落在某个可读映射区间内（要求 [addr, addr+8) 都在同一区间，
 * 避免读指针时跨越段边界越界）。先去指针标签再比较。 */
static bool is_addr_readable(const void *addr) {
    uintptr_t p = canon(addr);
    if (!plausible_pointer(p)) return false;
    uintptr_t end = p + sizeof(void *);
    for (int i = 0; i < g_rng_count; i++) {
        if (p >= g_rng_lo[i] && end <= g_rng_hi[i]) return true;
    }
    return false;
}

/* 从规范化地址读取一个指针，并返回其规范化形式。统一用于链表/字段遍历，
 * 保证所有后续比较都在去标签的同一空间内进行。调用前须 is_addr_readable。 */
static inline void *read_ptr(const void *addr) {
    void *raw = *(void **)(canon(addr));
    return (void *)canon(raw);
}

/* 从 /proc/self/maps 提取 libart.so 的最小起点与最大终点（多段合并） */
static bool get_libart_range(uintptr_t *out_lo, uintptr_t *out_hi) {
    int fd = my_open("/proc/self/maps", 0, 0);
    if (fd < 0) return false;
    char io_buf[4096];
    char line[512];
    size_t lp = 0;
    bool found = false;
    uintptr_t lo = 0, hi = 0;
    ssize_t rd;
    while ((rd = my_read(fd, io_buf, sizeof(io_buf))) > 0) {
        for (ssize_t i = 0; i < rd; i++) {
            char c = io_buf[i];
            if (c == '\n' || lp >= sizeof(line) - 1) {
                line[lp] = '\0';
                lp = 0;
                if (my_strstr(line, "/libart.so") != nullptr) {
                    unsigned long s = 0, e = 0;
                    if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
                        if (!found || (uintptr_t)s < lo) lo = (uintptr_t)s;
                        if ((uintptr_t)e > hi) hi = (uintptr_t)e;
                        found = true;
                    }
                }
                if (c != '\n') {
                    while (i < rd && io_buf[i] != '\n') i++;
                }
            } else {
                line[lp++] = c;
            }
        }
    }
    my_close(fd);
    if (found) {
        *out_lo = lo;
        *out_hi = hi;
    }
    return found;
}

/* 遍历 head 起的双向循环链表并计数；max_nodes 防止恶意/损坏环链的死循环。
 * head 须为规范化地址；遍历中读出的 next 指针逐一规范化后比较。 */
static int walk_list(uintptr_t head, int max_nodes) {
    if (!is_addr_readable((void *)head)) return -1;
    /* head->next 在 ListNode 偏移 0 */
    uintptr_t cur = (uintptr_t)read_ptr((void *)head);
    if (!is_addr_readable((void *)cur)) return -1;
    int count = 0;
    while (cur != head) {
        count++;
        if (count > max_nodes) return -1;
        if (!is_addr_readable((void *)cur)) return -1;
        uintptr_t nxt = (uintptr_t)read_ptr((void *)cur);  /* cur->next */
        if (!is_addr_readable((void *)nxt)) return -1;
        cur = nxt;
    }
    return count;
}

/* 暴力扫 Runtime 中 ClassLinker* 与 ClassLinker 内 class_loaders_ list 偏移 */
static bool scan_offsets(void *runtime, int *out_cl_off, int *out_list_off, int *out_count) {
    uintptr_t art_lo = 0, art_hi = 0;
    if (!get_libart_range(&art_lo, &art_hi)) {
        LOGD("[CLscan] libart range unavailable");
        return false;
    }
    LOGD("[CLscan] libart range 0x%lx-0x%lx", (unsigned long)art_lo, (unsigned long)art_hi);

    /* Runtime 对象在 Android 16 上很大，class_linker_ 可能在 0x500 之后；
     * ClassLinker 内 class_loaders_ 也未必在 0x500 内。给足扫描范围。 */
    const int OUTER_MAX = 0xE00;
    const int INNER_MAX = 0x800;
    const int STRIDE = (int)sizeof(void *);

    int vtable_hits = 0;   /* 诊断：找到多少个 vtable 落在 libart 的候选对象 */
    int list_closed = 0;   /* 诊断：其中有多少满足双向闭环 */

    uintptr_t runtime_addr = canon(runtime);
    for (int cl_off = 0; cl_off < OUTER_MAX; cl_off += STRIDE) {
        uintptr_t pp = runtime_addr + cl_off;
        if (!is_addr_readable((void *)pp)) continue;
        uintptr_t obj = (uintptr_t)read_ptr((void *)pp);
        if (!is_addr_readable((void *)obj)) continue;

        /* 特征 A：candidate 对象的 vtable（offset 0）落在 libart 段内 */
        uintptr_t vt = (uintptr_t)read_ptr((void *)obj);
        if (vt < art_lo || vt >= art_hi) continue;
        vtable_hits++;

        for (int list_off = 0; list_off < INNER_MAX; list_off += STRIDE) {
            uintptr_t head = obj + list_off;
            if (!is_addr_readable((void *)head)) continue;
            uintptr_t next = (uintptr_t)read_ptr((void *)head);          /* head->next @+0 */
            if (!is_addr_readable((void *)next)) continue;
            uintptr_t prev = (uintptr_t)read_ptr((void *)(head + sizeof(void *))); /* head->prev @+8 */
            if (!is_addr_readable((void *)prev)) continue;
            /* 特征 B：双向闭环（全部规范化后比较） */
            if (next == head) continue;
            uintptr_t next_prev = (uintptr_t)read_ptr((void *)(next + sizeof(void *)));
            if (next_prev != head) continue;
            uintptr_t prev_next = (uintptr_t)read_ptr((void *)prev);
            if (prev_next != head) continue;
            list_closed++;
            /* 特征 C：节点数合理 */
            int cnt = walk_list(head, 256);
            if (cnt >= 2) {
                *out_cl_off = cl_off;
                *out_list_off = list_off;
                *out_count = cnt;
                LOGD("[CLscan] LOCKED cl_off=0x%x list_off=0x%x count=%d",
                     cl_off, list_off, cnt);
                return true;
            }
        }
    }
    LOGD("[CLscan] no match in Runtime[0..0x%x]: libart-vtable candidates=%d, closed-lists=%d",
         OUTER_MAX, vtable_hits, list_closed);
    return false;
}

} /* anonymous */

extern "C" int detect_classloader_count(JNIEnv *env, int *out_cl_off, int *out_list_off) {
    if (!env) return -1;
    JavaVM *vm = nullptr;
    if (env->GetJavaVM(&vm) != JNI_OK || !vm) return -1;
    uintptr_t vm_addr = (uintptr_t)vm;

    /* 每次扫描前刷新可读区间表（取代 mincore） */
    refresh_readable_ranges();
    if (g_rng_count == 0) {
        LOGD("[CLscan] no readable ranges parsed from maps");
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    int vm_off = g_vm_runtime_off;
    int cl_off = g_cl_offset;
    int list_off = g_list_offset;
    pthread_mutex_unlock(&g_lock);

    /* ---- 首次：定位 Runtime + ClassLinker + list 三个偏移 ----
     *
     * 不能再写死 "Runtime = *(vm + sizeof(void*))"。该假设只在 Android 7-14
     * 成立；自更高版本起 JavaVMExt 因带 C++ 虚函数（vtable@0）+ 字段重排，
     * runtime_ 不再固定在 +8（实测 Pixel 6 Pro / Android 16 上 +8 失败）。
     *
     * 改为在 JavaVM 指针附近 [0, 0x40] 逐字探测候选 Runtime 指针，对每个
     * 可读候选跑一次 scan_offsets；能扫出"libart vtable + 双向闭环链表 +
     * count≥2"的那个才是真 Runtime。三特征组合误命中概率极低。 */
    if (vm_off < 0 || cl_off < 0 || list_off < 0) {
        const int VM_PROBE_MAX = 0x40;
        int found_count = -1;
        bool located = false;
        for (int off = 0; off <= VM_PROBE_MAX && !located; off += (int)sizeof(void *)) {
            if (!is_addr_readable((void *)(vm_addr + off))) continue;
            void *cand_runtime = read_ptr((void *)(vm_addr + off));
            if (!is_addr_readable(cand_runtime)) continue;
            int new_cl = -1, new_list = -1, new_count = -1;
            if (scan_offsets(cand_runtime, &new_cl, &new_list, &new_count)) {
                pthread_mutex_lock(&g_lock);
                g_vm_runtime_off = off;
                g_cl_offset = new_cl;
                g_list_offset = new_list;
                pthread_mutex_unlock(&g_lock);
                LOGD("[CLscan] located: vm_runtime_off=0x%x cl=0x%x list=0x%x count=%d",
                     off, new_cl, new_list, new_count);
                found_count = new_count;
                located = true;
            }
        }
        if (!located) {
            LOGD("[CLscan] could not locate Runtime/ClassLinker (ART layout unknown)");
            return -1;
        }
        if (out_cl_off) {
            pthread_mutex_lock(&g_lock);
            *out_cl_off = g_cl_offset;
            pthread_mutex_unlock(&g_lock);
        }
        if (out_list_off) {
            pthread_mutex_lock(&g_lock);
            *out_list_off = g_list_offset;
            pthread_mutex_unlock(&g_lock);
        }
        return found_count;
    }

    /* ---- 快速路径：三偏移全部缓存命中 ---- */
    if (!is_addr_readable((void *)(vm_addr + vm_off))) return -1;
    uintptr_t runtime = (uintptr_t)read_ptr((void *)(vm_addr + vm_off));
    if (!is_addr_readable((void *)runtime)) {
        /* JavaVM 布局漂移（极少见），重置触发重扫 */
        pthread_mutex_lock(&g_lock);
        g_vm_runtime_off = -1; g_cl_offset = -1; g_list_offset = -1;
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    uintptr_t clp = runtime + cl_off;
    if (!is_addr_readable((void *)clp)) return -1;
    uintptr_t cl = (uintptr_t)read_ptr((void *)clp);
    if (!is_addr_readable((void *)cl)) return -1;

    uintptr_t head = cl + list_off;
    if (!is_addr_readable((void *)head)) return -1;
    uintptr_t next = (uintptr_t)read_ptr((void *)head);
    if (!is_addr_readable((void *)next)
            || (uintptr_t)read_ptr((void *)(next + sizeof(void *))) != head) {
        /* 缓存的偏移在运行时不再有效（结构漂移）。重置偏移触发下次重扫 */
        LOGD("[CLscan] cached layout drift, resetting offsets");
        pthread_mutex_lock(&g_lock);
        g_vm_runtime_off = -1;
        g_cl_offset = -1;
        g_list_offset = -1;
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    int count = walk_list(head, 512);
    if (count < 0) return -1;
    if (out_cl_off) *out_cl_off = cl_off;
    if (out_list_off) *out_list_off = list_off;
    return count;
}

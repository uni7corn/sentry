#include "trap_detector.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#ifndef SIGTRAP
#define SIGTRAP 5
#endif

/* 仅在专用线程内使用 setjmp/longjmp，避免 SIGTRAP 被投递到 UI 线程导致跨线程 longjmp 崩溃 */
static sigjmp_buf s_trap_env;
static volatile int s_our_handler_ran;

static void trap_handler(int sig) {
    (void)sig;
    s_our_handler_ran = 1;
    siglongjmp(s_trap_env, 1);
}

static void *trap_thread_func(void *arg) {
    int *out_result = (int *)arg;
    LOGD("[Trap] thread start");
    s_our_handler_ran = 0;
    struct sigaction sa, old;
    sa.sa_handler = trap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGTRAP, &sa, &old) != 0) {
        LOGD("Trap detector: sigaction failed");
        *out_result = -1; /* 无法安装则标记为 Check skipped */
        return nullptr;
    }

    int r = sigsetjmp(s_trap_env, 1);
    if (r == 0) {
        /* 仅向本线程发送 SIGTRAP，避免主线程/UI 线程收到信号导致崩溃 */
        pid_t pid = my_getpid();
        int tid = my_gettid();
        if (tid >= 0 && my_tgkill(pid, tid, SIGTRAP) == 0) {
            /* 信号已发，应被本线程 handler 捕获并 longjmp，不会执行到这里 */
        }
        /* 若执行到这里说明本线程未 longjmp（例如 tgkill 不可用或信号被别处处理） */
        sigaction(SIGTRAP, &old, nullptr);
        LOGD("Trap detector: returned from tgkill(SIGTRAP), our handler did not run");
        *out_result = 1; /* 疑似被劫持 */
        return nullptr;
    }
    sigaction(SIGTRAP, &old, nullptr);
    *out_result = s_our_handler_ran ? 0 : 1; /* handler 运行则未劫持 */
    LOGD("[Trap] thread done: result=%d", *out_result);
    return nullptr;
}

int detect_trap_signal_handled(void) {
    int result = 0;
    pthread_t th;
    if (pthread_create(&th, nullptr, trap_thread_func, &result) != 0) {
        LOGD("Trap detector: pthread_create failed");
        return -1; /* 无法创建线程则 Check skipped */
    }
    pthread_join(th, nullptr);
    LOGD("[Trap] detect done: result=%d (0=OK 1=suspicious -1=skipped)", result);
    return result; /* 0=NORMAL, 1=DANGER, -1=SKIPPED */
}

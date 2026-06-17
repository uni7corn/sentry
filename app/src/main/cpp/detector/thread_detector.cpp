#include "thread_detector.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* Frida/Gum 注入栈专属线程名（comm 在 Linux 上截短至 15 字节）。
 *
 * 历史问题：旧列表含 gmain/gdbus/gthread/gpool/gjs-context —— 这些是 GLib 的标准
 * 线程名，任何合法使用 GLib 的库（如部分 GStreamer/3D 引擎/cairo 等）都会触发
 * 误报。Frida 在被注入进程里确实会启动 GLib 线程，但这类信号必须配合 maps 上
 * 的 Frida ELF 才有判断力，单独看 comm 不可靠。这里只保留几乎不可能在普通
 * App 中出现的关键词，宁可漏报也不要让"开始检测 → 立即标红"成为常态。
 */
static const char *FRIDA_THREAD_KEYWORDS[] = {
    "gum-js-loop",   /* GumJS 主循环 */
    "frida-agent",
    "frida-gadget",
    "frida-server",
    "frida-helper",
    "linjector",     /* Frida linjector 注入器 */
    nullptr
};

bool detect_frida_threads(void) {
    char dummy[1][256];
    return get_frida_thread_details(dummy, 0) > 0;
}

int get_frida_thread_details(char (*details)[256], int max_details) {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) {
        LOGD("Failed to open /proc/self/task");
        return -1;  /* 无法打开 task 目录时由 JNI 显示 Check skipped */
    }

    struct dirent *entry;
    int n = 0;
    char path[256];
    char buffer[256];

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);

        /* 先 syscall 再 libc 打开/读，提高兼容性 */
        int used_syscall = 0;
        int fd = open_with_fallback(path, 0, 0, &used_syscall);  /* O_RDONLY */
        if (fd < 0) {
            continue;
        }

        ssize_t bytes = read_with_fallback(fd, buffer, sizeof(buffer) - 1, used_syscall);
        my_close(fd);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            char *newline = (char *)my_strstr(buffer, "\n");
            if (newline) {
                *newline = '\0';
            }

            for (int i = 0; FRIDA_THREAD_KEYWORDS[i] != nullptr; i++) {
                if (my_strcasestr(buffer, FRIDA_THREAD_KEYWORDS[i]) != nullptr) {
                    LOGD("Suspicious thread found: %s (matches: %s)",
                         buffer, FRIDA_THREAD_KEYWORDS[i]);
                    if (details && n < max_details) {
                        snprintf(details[n], 256, "Thread %s: %s", entry->d_name, buffer);
                    }
                    n++;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return n;
}

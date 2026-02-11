#include "thread_detector.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char *FRIDA_THREAD_KEYWORDS[] = {
    "gmain",
    "gdbus",
    "pool-spawner",
    "frida-agent",
    "frida-gadget",
    "frida",
    "gum-js-loop",
    "gthread",
    "gpool",
    "gjs-context",
    "frida-helper",
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
        return 0;
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

        /* Use syscall to bypass libc hook */
        int fd = my_open(path, 0, 0);  /* O_RDONLY */
        if (fd < 0) {
            continue;
        }

        ssize_t bytes = my_read(fd, buffer, sizeof(buffer) - 1);
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

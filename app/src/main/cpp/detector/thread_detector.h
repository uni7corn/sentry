#ifndef THREAD_DETECTOR_H
#define THREAD_DETECTOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_threads(void);

/** Fills details array with suspicious thread info, returns count. Uses syscall to bypass libc hook. */
int get_frida_thread_details(char (*details)[256], int max_details);

#ifdef __cplusplus
}
#endif

#endif // THREAD_DETECTOR_H

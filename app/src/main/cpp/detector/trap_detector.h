#ifndef TRAP_DETECTOR_H
#define TRAP_DETECTOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 陷阱检测：注册 SIGTRAP 处理函数，通过 syscall 发送 SIGTRAP，若本进程信号未被
 * 我们自己的 handler 捕获（longjmp 回检测点），则疑为被 Frida 等劫持。
 * @return 0=我们的 handler 已运行，1=疑似被劫持，-1=无法检查（信号/线程设置失败，显示 Check skipped）
 */
int detect_trap_signal_handled(void);

#ifdef __cplusplus
}
#endif

#endif // TRAP_DETECTOR_H

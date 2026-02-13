#ifndef SO_INTEGRITY_H
#define SO_INTEGRITY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 仅检查关键函数（open/read/strcmp/strstr）头部是否为 Trampoline，误报率低。
 * @return 0=正常, 1=检测到疑似 Hook
 */
int check_critical_functions(void);

/**
 * 检查 libc 等系统库是否被 Inline Hook（通过 dl_iterate_phdr + 内存特征扫描，不读文件）。
 * 避免 SELinux 禁止读 /system、/apex 及 XOM 导致的不可用。
 * @return 0=正常, 1=检测到疑似 Hook, -1=未找到 libc
 */
int check_libc_text_integrity(void);

/**
 * 扫描 /proc/self/maps 中可疑的匿名可执行段（按 perms 含 'x' 精确定位），辅助发现 Frida Trampoline。
 * @return 0=未发现, 1=发现可疑段, -1=读取失败
 */
int scan_suspicious_anonymous_rx_memory(void);

/**
 * 快速预检：Frida 默认端口 27042 是否在监听。
 * @return 0=未检测到, 1=检测到
 */
int check_frida_port(void);

/**
 * GOT 表完整性：检查 open/read/strcmp 等解析地址是否在 libc 范围内；
 * 若被 Frida 劫持，地址会指向 libc 外的 trampoline。不需读磁盘/代码段，适用于 Android 10+。
 * @return 0=正常, 1=检测到 GOT 劫持, -1=未找到 libc
 */
int detect_frida_got_hook(void);

#ifdef __cplusplus
}
#endif

#endif // SO_INTEGRITY_H

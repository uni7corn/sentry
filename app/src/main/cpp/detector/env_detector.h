#ifndef ENV_DETECTOR_H
#define ENV_DETECTOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magisk-specific detection - returns count, DANGER when > 0
int env_detect_magisk(char (*details)[256], int max_details);

// Bootloader state - out_status: 0=NORMAL,1=WARNING,2=DANGER; returns detail count
int env_detect_bootloader(int *out_status, char (*details)[256], int max_details);

// Suspicious files (Frida, adb paths) - returns count; no debug_ramdisk
int env_detect_suspicious_files(char (*details)[256], int max_details);

// Dirty page / memory injection: Smaps Private_Dirty + VMap + Pagemap bit 55; returns count, DANGER when > 0
int env_detect_zygisk_injection(char (*details)[256], int max_details);

// Read /proc/version for fingerprint (caller must free returned string)
char *env_read_proc_version(void);

// Emulator file check (caller provides build props for string matching)
int env_detect_emulator_files(const char *hardware, const char *product,
                              const char *device, const char *brand,
                              char (*details)[256], int max_details);

// Check if a port is open on 127.0.0.1 (for ADB 5555 etc.), uses syscall
bool env_check_port_open(int port);

// ADB/developer mode detection: multi-channel (syscall), returns count, fills details
// Ports 5555-5558, /proc/net/tcp, adbd process, /sys/class/android_usb
int env_detect_adb(char (*details)[256], int max_details);

// Container/cgroup check - returns count, DANGER when > 0
int env_detect_cgroup(char (*details)[256], int max_details);

// Dangerous Apps: verify APK has assets/xposed_init, read modules.list (syscall)
// apk_paths, pkg_names: parallel arrays, count elements; fills out_pkgs with package names, returns count
int env_verify_xposed_modules(const char **apk_paths, const char **pkg_names, int count,
                              char (*out_pkgs)[256], int max_out);

// Device fingerprint spoof: per-partition build-prop consistency + eng/aosp/test-keys markers.
// out_status: 0=NORMAL,1=WARNING,2=DANGER; returns detail count.
int env_detect_fingerprint_spoof(int *out_status, char (*details)[256], int max_details);

// Read a single system property into caller buffer (anti-hook via __system_property_read_callback).
// Returns value length (0 if unavailable / non-Android).
int env_read_prop(const char *name, char *buf, int buf_len);

#ifdef __cplusplus
}
#endif

#endif /* ENV_DETECTOR_H */

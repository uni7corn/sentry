#ifndef MEMORY_SCANNER_H
#define MEMORY_SCANNER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_memory_signatures(void);
bool scan_maps_for_frida(void);

/** Fills details array with findings, returns count. Uses syscall to bypass libc hook. */
int get_memory_signature_details(char (*details)[256], int max_details);

/** Same as above; advanced_checks=true uses 4KB threshold for anon exec memory (vs 128KB default). */
int get_memory_signature_details_ex(char (*details)[256], int max_details, int advanced_checks);

/** Returns true if addr falls in suspicious anonymous r-x memory (excludes dalvik-jit/scudo etc). Used by PLT/GOT check. */
bool is_address_in_suspicious_anon_exec(uint64_t addr);

#ifdef __cplusplus
}
#endif

#endif // MEMORY_SCANNER_H

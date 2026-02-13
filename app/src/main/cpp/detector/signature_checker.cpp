#include "signature_checker.h"
#include <cstring>
#include <cctype>

#ifndef EXPECTED_SIGNATURE_SHA256
#define EXPECTED_SIGNATURE_SHA256 ""
#endif

static void to_lower_hex(char *out, const char *in, int max_len) {
    for (int i = 0; i < max_len && in[i]; i++) {
        char c = in[i];
        out[i] = (char) (std::isalpha((unsigned char) c) ? (std::tolower((unsigned char) c)) : c);
    }
    out[max_len - 1] = '\0';
}

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int verify_app_signature(const char *current_sha256_hex) {
    const char *expected = EXPECTED_SIGNATURE_SHA256;
    if (!expected || expected[0] == '\0') {
        /* 未配置预期签名（如 Debug 构建）：跳过校验 */
        return 0;
    }
    if (!current_sha256_hex) {
        return 2; /* 无法获取当前签名 */
    }
    /* SHA-256 十六进制长度为 64 */
    const int len = 64;
    char cur_lower[65];
    char exp_lower[65];
    int i = 0;
    for (; i < len && current_sha256_hex[i] && expected[i]; i++) {
        if (!is_hex_char(current_sha256_hex[i])) {
            return 2;
        }
        cur_lower[i] = (char) std::tolower((unsigned char) current_sha256_hex[i]);
        exp_lower[i] = (char) std::tolower((unsigned char) expected[i]);
    }
    if (i != len || current_sha256_hex[i] != '\0' || expected[i] != '\0') {
        return 2; /* 长度不对或未配置完整 */
    }
    cur_lower[len] = exp_lower[len] = '\0';
    return (std::memcmp(cur_lower, exp_lower, len) == 0) ? 0 : 2;
}

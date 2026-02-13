#ifndef SENTRY_SIGNATURE_CHECKER_H
#define SENTRY_SIGNATURE_CHECKER_H

/**
 * 应用签名校验：防止二次打包。
 * 预期签名 SHA-256（小写十六进制 64 字符）由构建时注入 EXPECTED_SIGNATURE_SHA256。
 * 若未注入（空），则跳过校验返回 0（NORMAL）。
 *
 * @param current_sha256_hex 当前应用签名证书的 SHA-256 十六进制字符串（64 字符，可含大小写）
 * @return 0 = 校验通过或跳过，2 = 签名不匹配（DANGER，疑似二次打包）
 */
int verify_app_signature(const char *current_sha256_hex);

#endif /* SENTRY_SIGNATURE_CHECKER_H */

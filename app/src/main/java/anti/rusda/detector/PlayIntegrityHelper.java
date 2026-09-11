package anti.rusda.detector;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;

import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Play Integrity —— 本地能做的部分（不联网、不需要 Google Cloud 项目号）。
 *
 * <p>真正的 Play Integrity 令牌由 Google Play 服务签发、需服务端（配 Cloud 项目号）解码才有权威
 * 结论，App 本地无法自证。本类退而求其次，做 Play Integrity 会依赖的<b>本地可观测信号</b>并给出
 * 一个<b>近似</b>裁决（明确标注为近似）：
 * <ul>
 *   <li>Play 组件：GMS（com.google.android.gms）/ Play Store（com.android.vending）是否安装、启用、版本；
 *       缺 GMS → 设备几乎必然过不了 Play Integrity；</li>
 *   <li>GMS 签名核对 Google 官方证书（识破 microG / 伪 GMS）；</li>
 *   <li>Play Protect（Verify Apps）开关；</li>
 *   <li>本地聚合 MEETS_BASIC / DEVICE / STRONG_INTEGRITY：复用 Key Attestation 强校验结果
 *       （链可信 + 未吊销 + deviceLocked + verifiedBoot + 硬件级）、指纹未伪装、非模拟器、补丁新旧。</li>
 * </ul>
 * 本项 warnOnly 且封顶 WARNING（纯参考，不与 Bootloader/Root/Attestation 重复扣分）。
 */
public final class PlayIntegrityHelper {

    private static final String PKG_GMS = "com.google.android.gms";
    private static final String PKG_PLAY_STORE = "com.android.vending";

    /** Google apps 官方签名证书 SHA-256（GMS / Play Store 均以此签名） */
    private static final String GOOGLE_SIG_SHA256 =
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83";

    private static final int SEC_TEE = 1;

    private PlayIntegrityHelper() {
    }

    /**
     * @param report        共享的 attestation 结果（可为 null）
     * @param fpStatus      指纹伪装项状态（DetectionResult.STATUS_*）
     * @param emulatorStatus 模拟器项状态
     */
    public static DetectionResult evaluate(Context context,
                                           KeyAttestationHelper.AttestationReport report,
                                           int fpStatus, int emulatorStatus) {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        if (context == null) {
            details.add("Context unavailable");
            return new DetectionResult("Play Integrity (Local)", "Check skipped",
                    DetectionResult.STATUS_NORMAL, 10, details, true);
        }
        PackageManager pm = context.getPackageManager();

        /* ── Play 组件 ── */
        details.add("═══ Play Components ═══");
        boolean gmsPresent = false, gmsEnabled = false, gmsSigOk = false;
        long gmsVer = -1;
        try {
            PackageInfo gi = pm.getPackageInfo(PKG_GMS, 0);
            gmsPresent = true;
            gmsVer = versionCode(gi);
            gmsEnabled = isEnabled(pm, PKG_GMS);
            gmsSigOk = signatureMatches(pm, PKG_GMS, GOOGLE_SIG_SHA256);
            details.add("GMS: installed, v" + gmsVer + (gmsEnabled ? ", enabled" : ", DISABLED"));
        } catch (PackageManager.NameNotFoundException e) {
            details.add("GMS (com.google.android.gms): NOT installed");
        } catch (Throwable t) {
            details.add("GMS check error: " + t.getClass().getSimpleName());
        }

        boolean storePresent = false;
        try {
            PackageInfo si = pm.getPackageInfo(PKG_PLAY_STORE, 0);
            storePresent = true;
            details.add("Play Store: installed, v" + versionCode(si)
                    + (isEnabled(pm, PKG_PLAY_STORE) ? ", enabled" : ", DISABLED"));
        } catch (PackageManager.NameNotFoundException e) {
            details.add("Play Store (com.android.vending): NOT installed");
        } catch (Throwable t) {
            details.add("Play Store check error: " + t.getClass().getSimpleName());
        }

        if (gmsPresent) {
            details.add("GMS signature: " + (gmsSigOk ? "matches Google cert ✓" : "does NOT match Google cert (microG / fake GMS?) ✗"));
            if (!gmsSigOk) status = DetectionResult.STATUS_WARNING;
        } else {
            status = DetectionResult.STATUS_WARNING;
        }

        /* ── Play Protect / Verify Apps ── */
        details.add("═══ Play Protect (Verify Apps) ═══");
        int verifyEnable = globalInt(context, "package_verifier_enable", -1);
        int verifyConsent = globalInt(context, "package_verifier_user_consent", 0);
        boolean verifyOn = verifyEnable == 1 || verifyConsent == 1;
        details.add("Verify Apps: " + (verifyEnable < 0 ? "unknown"
                : (verifyOn ? "enabled" : "disabled")));

        /* ── 本地聚合裁决 ── */
        details.add("═══ Local Verdict (approximation) ═══");
        boolean attTrusted = report != null && report.available
                && report.cryptoChainOk && report.rootPinned && !report.revoked
                && report.challengeMatch && report.deviceLocked && report.verifiedBoot
                && report.securityLevel >= SEC_TEE;

        boolean fpClean = fpStatus != DetectionResult.STATUS_DANGER;
        boolean notEmulator = emulatorStatus == DetectionResult.STATUS_NORMAL;
        boolean recentPatch = securityPatchWithinMonths(18);

        boolean basic = gmsPresent && fpClean && emulatorStatus != DetectionResult.STATUS_DANGER;
        boolean device = attTrusted && fpClean;
        boolean strong = device && recentPatch && notEmulator;

        details.add("MEETS_BASIC_INTEGRITY:  " + yn(basic)
                + (basic ? "" : "  (GMS/emulator/fingerprint)"));
        details.add("MEETS_DEVICE_INTEGRITY: " + yn(device)
                + (device ? "" : "  (needs trusted attestation + locked/verified boot)"));
        details.add("MEETS_STRONG_INTEGRITY: " + yn(strong)
                + (strong ? "" : "  (device integrity + recent patch)"));
        details.add("Note: local approximation only - authoritative verdict requires Google server-side decode");
        details.add("Real Play Integrity token not requested (needs a Google Cloud project number + backend)");

        if (!device) status = DetectionResult.STATUS_WARNING;

        String summary = status == DetectionResult.STATUS_NORMAL
                ? "Local Play Integrity signals look healthy"
                : "Local Play Integrity: some signals would fail (see details)";
        /* warnOnly：仅提示不扣分（避免与 Bootloader/Root/Attestation 重复计分） */
        return new DetectionResult("Play Integrity (Local)", summary, status, 10, details, true);
    }

    // ── helpers ──

    private static String yn(boolean b) {
        return b ? "PASS ✓" : "FAIL ✗";
    }

    @SuppressWarnings("deprecation")
    private static long versionCode(PackageInfo pi) {
        if (pi == null) return -1;
        if (Build.VERSION.SDK_INT >= 28) return pi.getLongVersionCode();
        return pi.versionCode;
    }

    private static boolean isEnabled(PackageManager pm, String pkg) {
        try {
            return pm.getApplicationInfo(pkg, 0).enabled;
        } catch (Throwable t) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean signatureMatches(PackageManager pm, String pkg, String expectedSha256) {
        try {
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi.signingInfo == null) return false;
                sigs = pi.signingInfo.getApkContentsSigners();
            } else {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }
            if (sigs == null) return false;
            for (Signature s : sigs) {
                if (expectedSha256.equalsIgnoreCase(sha256Hex(s.toByteArray()))) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static int globalInt(Context ctx, String key, int def) {
        try {
            return Settings.Global.getInt(ctx.getContentResolver(), key, def);
        } catch (Throwable t) {
            return def;
        }
    }

    private static boolean securityPatchWithinMonths(int months) {
        String patch = Build.VERSION.SECURITY_PATCH;
        if (patch == null || patch.isEmpty()) return false;
        try {
            Date d = new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch);
            if (d == null) return false;
            long monthsAgo = (System.currentTimeMillis() - d.getTime()) / (30L * 24 * 60 * 60 * 1000);
            return monthsAgo <= months;
        } catch (ParseException e) {
            return false;
        }
    }

    private static String sha256Hex(byte[] data) {
        if (data == null) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(data);
            StringBuilder sb = new StringBuilder(h.length * 2);
            for (byte b : h) sb.append(String.format(Locale.US, "%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}

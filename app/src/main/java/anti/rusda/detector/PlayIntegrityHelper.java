package anti.rusda.detector;

import android.content.Context;
import android.util.Base64;

import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Play Integrity API 客户端封装。
 * 获取 token 后需由服务端验证（注入 PlayIntegrityVerifier）。
 * 无 Play 服务或验证失败时合理降级，避免误杀。
 */
public class PlayIntegrityHelper {

    private static final int TIMEOUT_SECONDS = 15;

    private final Context context;
    private final PlayIntegrityVerifier verifier;

    public PlayIntegrityHelper(Context context, PlayIntegrityVerifier verifier) {
        this.context = context;
        this.verifier = verifier;
    }

    public PlayIntegrityHelper(Context context) {
        this(context, null);
    }

    /**
     * 同步执行 Play Integrity 检测。
     * 无 Play Store/Play Services 的设备（如华为等国产厂商）视为通过，避免误报。
     * @return [status, summary, detail]
     */
    public String[] runDetectionSync() {
        if (context == null) {
            return new String[]{
                    String.valueOf(DetectionResult.STATUS_NORMAL),
                    "No context for Play Integrity - passed",
                    "Play Integrity check skipped"
            };
        }

        IntegrityManager manager;
        try {
            manager = IntegrityManagerFactory.create(context);
        } catch (Throwable t) {
            /* 无 GMS 时 create 可能抛异常，视为通过 */
            return new String[]{
                    String.valueOf(DetectionResult.STATUS_NORMAL),
                    "Play Services not available - passed (OEM device without GMS)",
                    t.getMessage() != null ? t.getMessage() : "IntegrityManagerFactory.create failed"
            };
        }
        byte[] nonceBytes = new byte[32];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.encodeToString(nonceBytes, Base64.NO_WRAP);

        IntegrityTokenRequest request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build();

        final CountDownLatch latch = new CountDownLatch(1);
        final int[] statusHolder = {DetectionResult.STATUS_DANGER};
        final String[] summaryHolder = {"Verification failed"};
        final String[] detailHolder = {"Unknown error"};

        manager.requestIntegrityToken(request)
                .addOnSuccessListener(response -> {
                    String token = response.token();
                    if (verifier != null) {
                        statusHolder[0] = verifier.verifyToken(token);
                        summaryHolder[0] = statusHolder[0] == DetectionResult.STATUS_NORMAL
                                ? "Device integrity verified"
                                : statusHolder[0] == DetectionResult.STATUS_WARNING
                                        ? "Basic integrity only"
                                        : "Integrity verification failed";
                        detailHolder[0] = "Server verified token";
                    } else {
                        statusHolder[0] = DetectionResult.STATUS_WARNING;
                        summaryHolder[0] = "Token obtained, server verification not configured";
                        detailHolder[0] = "Configure PlayIntegrityVerifier for full verification";
                    }
                    latch.countDown();
                })
                .addOnFailureListener(e -> {
                    String msg = e != null ? e.getMessage() : "Unknown";
                    /* 无 Play Store/Play Services 的设备（华为等）视为通过，避免误报 */
                    if (msg != null && isPlayServicesUnavailable(msg)) {
                        statusHolder[0] = DetectionResult.STATUS_NORMAL;
                        summaryHolder[0] = "Play Store/Services not installed - passed (OEM without GMS)";
                        detailHolder[0] = "Device has no Google Play - treat as pass to avoid false positive";
                    } else {
                        statusHolder[0] = DetectionResult.STATUS_WARNING;
                        summaryHolder[0] = "Play Integrity request failed";
                        detailHolder[0] = msg != null ? msg : "No details";
                    }
                    latch.countDown();
                });

        try {
            if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                statusHolder[0] = DetectionResult.STATUS_WARNING;
                summaryHolder[0] = "Play Integrity request timed out";
                detailHolder[0] = "Request did not complete within " + TIMEOUT_SECONDS + " seconds";
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            statusHolder[0] = DetectionResult.STATUS_WARNING;
            summaryHolder[0] = "Play Integrity check interrupted";
            detailHolder[0] = e.getMessage();
        }

        return new String[]{String.valueOf(statusHolder[0]), summaryHolder[0], detailHolder[0]};
    }

    /** 判断是否为「无 Play Store/Play Services」类错误，此类设备视为通过 */
    private static boolean isPlayServicesUnavailable(String msg) {
        if (msg == null) return false;
        String m = msg.toLowerCase();
        return m.contains("api_not_available")
                || m.contains("play_store_not_found")
                || m.contains("play store")
                || m.contains("play services")
                || m.contains("google play services");
    }
}

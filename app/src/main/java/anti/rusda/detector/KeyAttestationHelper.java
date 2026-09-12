package anti.rusda.detector;

import android.content.Context;
import android.os.Build;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Android Key Attestation（密钥认证）——两层能力：
 *
 * <p><b>1. RootOfTrust（供 Bootloader 项）</b>：解析 TEE/TrustZone 证明证书扩展
 * （OID 1.3.6.1.4.1.11129.2.1.17）中的 verifiedBootKey / deviceLocked / verifiedBootState /
 * verifiedBootHash，识别 boot.img 是否被修补、bootloader 是否解锁。
 *
 * <p><b>2. 证书链强校验（供 Key Attestation Trust 项）</b>：仅看链结构与 RootOfTrust 不足以识破
 * 泄露/伪造 keybox——伪造链同样 chain 到 Google 根且 deviceLocked=true。本类补齐：
 * <ul>
 *   <li>证书链密码学签名逐级校验（断链 → 伪造/损坏）；</li>
 *   <li>根证书 pinning：链末公钥必须命中内置 Google 硬件认证根集合；</li>
 *   <li>吊销核对：任一 cert 序列号命中 Google attestation status list（KEY_COMPROMISE）→ 泄露 keybox；</li>
 *   <li>挑战值核对：扩展内 attestationChallenge 必须 == 本次随机挑战（识破回放/借用的罐装链）；</li>
 *   <li>安全级别：解析 attestationSecurityLevel / keymasterSecurityLevel（Software=0/TEE=1/StrongBox=2），
 *       替换以往写死的 hardwareBacked=Yes；</li>
 *   <li>attestationApplicationId：核对包名，识破借用他 App 的链。</li>
 * </ul>
 *
 * <p><b>关于 attest-key 误报</b>：本类刻意使用 {@code PURPOSE_SIGN}（而非 {@code PURPOSE_ATTEST_KEY}），
 * 因此不会走 attest-key 模式，也就不会撞上 KeyMint 给 attest-key 证书发空 KeyUsage（RFC 违规）导致的
 * “不受信任”误报——那与 keybox 好坏无关，不能当作伪造信号。故本类<strong>不</strong>以 KeyUsage 判伪。
 *
 * <p>吊销名单来源：内置快照 {@code assets/attestation/status.json} + 后台 best-effort 联网刷新
 * （{@code https://android.googleapis.com/attestation/status}）；根证书来自内置
 * {@code assets/attestation/google_roots.json}。完全离线亦可工作（用快照）。
 *
 * <p>需 API 28+（setAttestationChallenge）。
 */
public class KeyAttestationHelper {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ATTESTATION_KEY_ALIAS = "sentry_attestation_key";
    /** Android Key Attestation extension OID */
    private static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    /** Keymaster ROOT_OF_TRUST tag in AuthorizationList */
    private static final int KM_TAG_ROOT_OF_TRUST = 704;

    /** Verified boot state: Verified=0, SelfSigned=1, Unverified=2, Failed=3 */
    private static final int BOOT_VERIFIED = 0;
    private static final int BOOT_SELF_SIGNED = 1;
    private static final int BOOT_UNVERIFIED = 2;
    private static final int BOOT_FAILED = 3;

    /** SecurityLevel enum (KeyDescription) */
    private static final int SEC_SOFTWARE = 0;
    private static final int SEC_TEE = 1;
    private static final int SEC_STRONGBOX = 2;

    private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";
    private static final String ASSET_STATUS = "attestation/status.json";
    private static final String ASSET_ROOTS = "attestation/google_roots.json";
    private static final int HTTP_TIMEOUT_MS = 6_000;

    /* 进程内缓存（首次加载后复用；后台线程调用，volatile 足够） */
    private static volatile Set<String> sRevokedSerials;   // lowercase hex
    private static volatile String sRevokedSource;         // "network" | "bundled" | "unavailable"
    private static volatile List<PublicKey> sGoogleRootKeys;

    // ─────────────────────────────────────────────────────────────────────────
    // Public result object (shared by Bootloader / Attestation Trust / Play Integrity)
    // ─────────────────────────────────────────────────────────────────────────

    /** 一次 attestation 运行的完整结果，供多项检测共享（避免生成多把密钥）。 */
    public static final class AttestationReport {
        // ── RootOfTrust 视图（Bootloader 项使用，输出与旧 runAttestationSync 保持一致）
        public int rootStatus = DetectionResult.STATUS_NORMAL;
        public String rootSummary = "Boot verified";
        public final List<String> rootLines = new ArrayList<>();

        // ── 强校验视图（Key Attestation Trust 项使用）
        public int trustStatus = DetectionResult.STATUS_NORMAL;
        public String trustSummary = "Attestation chain trusted";
        public final List<String> trustLines = new ArrayList<>();

        // ── 供 Play Integrity 本地聚合的原子信号
        public boolean available = false;         // attestation 实际跑通、拿到扩展
        public boolean deviceLocked = false;
        public boolean verifiedBoot = false;      // verifiedBootState == Verified
        public boolean cryptoChainOk = false;     // 链内逐级签名校验通过
        public boolean rootPinned = false;        // 链末命中 Google 根
        public boolean revoked = false;           // 命中吊销名单
        public boolean challengeMatch = false;
        public int securityLevel = -1;            // 0/1/2，-1 未知

        // ── 供 System Property Integrity 做"属性 vs 硬件"交叉验证的 TEE 真值
        public boolean devicePropsAttested = false;  // 是否带设备属性认证(API31+)
        public int osVersion = -1;                    // 编码 major*10000+minor*100+sub
        public int osPatchLevel = -1;                 // YYYYMM
        public String idBrand, idDevice, idProduct, idManufacturer, idModel;  // TEE 认证的机身标识
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entry points
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 运行一次 Key Attestation 并做完整解析 + 强校验。返回的 {@link AttestationReport}
     * 同时供 Bootloader、Key Attestation Trust、Play Integrity 三项复用。
     */
    public static AttestationReport runFullAttestation(Context context) {
        AttestationReport r = new AttestationReport();

        if (Build.VERSION.SDK_INT < 28) {
            String msg = "Key attestation requires API 28+ (current: " + Build.VERSION.SDK_INT + ")";
            r.rootStatus = DetectionResult.STATUS_NORMAL;
            r.rootSummary = "Key attestation not supported on this API level (passed)";
            r.rootLines.add(msg);
            r.trustStatus = DetectionResult.STATUS_NORMAL;
            r.trustSummary = "Attestation trust check not supported on this API level (passed)";
            r.trustLines.add(msg);
            return r;
        }

        KeyStore ks = null;
        try {
            byte[] challenge = new byte[32];
            new java.security.SecureRandom().nextBytes(challenge);

            ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);

            /* 优先带"设备属性认证"(API31+：brand/device/product/manufacturer/model 由 TEE 附带)，
             * 供 System Property Integrity 项做硬件交叉验证；不支持的机型抛错则回退到不带该标志，
             * 保证证书链对 Bootloader / Attestation Trust 仍可用。 */
            Certificate[] chain = null;
            if (Build.VERSION.SDK_INT >= 31) {
                try {
                    generateAttestationKey(challenge, true);
                    chain = ks.getCertificateChain(ATTESTATION_KEY_ALIAS);
                    if (chain != null && chain.length > 0) r.devicePropsAttested = true;
                } catch (Throwable t) {
                    deleteAttestationKey(ks);
                    chain = null;
                }
            }
            if (chain == null || chain.length == 0) {
                r.devicePropsAttested = false;
                deleteAttestationKey(ks);
                generateAttestationKey(challenge, false);
                chain = ks.getCertificateChain(ATTESTATION_KEY_ALIAS);
            }

            if (chain == null || chain.length == 0) {
                r.rootStatus = DetectionResult.STATUS_WARNING;
                r.rootSummary = "Key attestation: no certificate chain";
                r.rootLines.add("Empty certificate chain");
                r.trustStatus = DetectionResult.STATUS_WARNING;
                r.trustSummary = "Attestation trust: no certificate chain";
                r.trustLines.add("Empty certificate chain - cannot validate");
                return r;
            }

            X509Certificate leaf = (X509Certificate) chain[0];
            byte[] extValue = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID);

            fillRootOfTrust(r, chain, extValue);          // Bootloader 视图
            fillTrust(context, r, chain, extValue, challenge);  // 强校验视图
            parseDeviceIdentity(extValue, r);             // TEE 机身标识 / OS 版本·补丁（供属性交叉验证）

            return r;
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            r.rootStatus = DetectionResult.STATUS_WARNING;
            r.rootSummary = "Key attestation failed: " + msg;
            r.rootLines.add("Exception: " + msg);
            r.trustStatus = DetectionResult.STATUS_WARNING;
            r.trustSummary = "Attestation trust check failed: " + msg;
            r.trustLines.add("Exception: " + msg);
            return r;
        } finally {
            if (ks != null) deleteAttestationKey(ks);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RootOfTrust view (Bootloader) — 保持旧 runAttestationSync 的输出与判定
    // ─────────────────────────────────────────────────────────────────────────

    private static void fillRootOfTrust(AttestationReport r, Certificate[] chain, byte[] extValue) {
        int statusFromChain = DetectionResult.STATUS_NORMAL;
        if (chain.length < 2) {
            r.rootLines.add("Certificate chain too short (expected 2+, got " + chain.length + ")");
            statusFromChain = DetectionResult.STATUS_WARNING;
        }

        if (extValue == null || extValue.length == 0) {
            r.rootStatus = DetectionResult.STATUS_WARNING;
            r.rootSummary = "Key attestation: extension missing (device may not support TEE attestation)";
            r.rootLines.add("No attestation extension in certificate");
            return;
        }

        RootOfTrust rot = parseRootOfTrust(extValue);
        if (rot == null) {
            r.rootStatus = DetectionResult.STATUS_NORMAL;
            r.rootSummary = "Key attestation: format not recognized on this device (passed)";
            r.rootLines.add("RootOfTrust structure not recognized on this device (OEM-specific format)");
            r.rootLines.add("TEE AVB values (verifiedBootKey, verifiedBootHash, deviceLocked) unavailable - see AVB (System Properties) above for fallback");
            return;
        }

        r.deviceLocked = rot.deviceLocked;
        r.verifiedBoot = (rot.verifiedBootState == BOOT_VERIFIED);

        int status = Math.max(DetectionResult.STATUS_NORMAL, statusFromChain);
        boolean isEmulator = isLikelyEmulator();
        if (rot.verifiedBootKeyAllZeros && !isEmulator) {
            status = DetectionResult.STATUS_DANGER;
        } else if (rot.verifiedBootKeyAllZeros && isEmulator) {
            r.rootLines.add("verifiedBootKey all zeros (emulator - not flagged as DANGER)");
        }
        if (!rot.deviceLocked) status = DetectionResult.STATUS_DANGER;
        if (rot.verifiedBootState == BOOT_UNVERIFIED || rot.verifiedBootState == BOOT_FAILED) status = DetectionResult.STATUS_DANGER;
        if (rot.verifiedBootState == BOOT_SELF_SIGNED && status != DetectionResult.STATUS_DANGER) status = DetectionResult.STATUS_WARNING;

        long uptimeMs = SystemClock.elapsedRealtime();
        if (uptimeMs < 60000) {
            r.rootLines.add("Device recently booted (< 1 min) - possible bypass attempt");
            status = Math.max(status, DetectionResult.STATUS_WARNING);
        }

        r.rootLines.add("═══ Device State ═══");
        r.rootLines.add("deviceLocked: " + rot.deviceLocked + (rot.deviceLocked ? " ✓" : " ✗"));
        r.rootLines.add("verifiedBootState: " + rot.verifiedBootStateName + (rot.verifiedBootState == BOOT_VERIFIED ? " ✓" : " ✗"));
        r.rootLines.add("verifiedBootKey: " + rot.verifiedBootKeyHex);
        r.rootLines.add("verifiedBootHash: " + rot.verifiedBootHashHex);
        if (rot.verifiedBootKeyAllZeros) r.rootLines.add("verifiedBootKey is all zeros - boot may have been patched");

        r.rootLines.add("═══ Security Impact ═══");
        boolean hasImpact = false;
        if (!rot.deviceLocked) { r.rootLines.add("• Bootloader is UNLOCKED"); hasImpact = true; }
        if (rot.verifiedBootState == BOOT_UNVERIFIED || rot.verifiedBootState == BOOT_FAILED) {
            r.rootLines.add("• AVB verification DISABLED/SKIPPED");
            r.rootLines.add("• Boot images are NOT verified");
            hasImpact = true;
        }
        if (rot.verifiedBootKeyAllZeros || !rot.deviceLocked) { r.rootLines.add("• Custom firmware can be flashed"); hasImpact = true; }
        if (status == DetectionResult.STATUS_DANGER || status == DetectionResult.STATUS_WARNING) {
            r.rootLines.add("• Banking apps may refuse to run");
            r.rootLines.add("• Play Integrity will fail");
            hasImpact = true;
        }
        if (!hasImpact) r.rootLines.add("• No significant security impact");

        r.rootStatus = status;
        r.rootSummary = status == DetectionResult.STATUS_DANGER
                ? "Boot may be patched or bootloader unlocked"
                : status == DetectionResult.STATUS_WARNING ? "Self-signed or uncertain boot" : "Boot verified";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Strong trust view (Key Attestation Trust)
    // ─────────────────────────────────────────────────────────────────────────

    private static void fillTrust(Context context, AttestationReport r, Certificate[] chain,
                                  byte[] extValue, byte[] challenge) {
        List<String> d = r.trustLines;
        int status = DetectionResult.STATUS_NORMAL;
        int warnSignals = 0;

        d.add("Chain length: " + chain.length + " cert(s)");

        /* 扩展缺失：设备不支持 TEE attestation，无法做强校验（不判危险，避免误伤无 TEE 机型） */
        if (extValue == null || extValue.length == 0) {
            r.trustStatus = DetectionResult.STATUS_WARNING;
            r.trustSummary = "No attestation extension - hardware attestation unsupported";
            d.add("No attestation extension: cannot validate hardware trust on this device");
            return;
        }
        r.available = true;

        /* 1) 链内密码学逐级校验 */
        r.cryptoChainOk = verifyChainLinks(chain);
        if (r.cryptoChainOk) {
            d.add("Chain signatures: each cert verified by its issuer ✓");
        } else {
            status = DetectionResult.STATUS_DANGER;
            d.add("Chain signatures BROKEN - a cert is not signed by the next (forged/corrupt) ✗");
        }

        /* 2) 根证书 pinning：链末命中内置 Google 硬件认证根 */
        List<PublicKey> roots = loadGoogleRootKeys(context);
        r.rootPinned = isChainRootedInGoogle(chain, roots);
        if (roots == null || roots.isEmpty()) {
            d.add("Google root set unavailable (bundled roots missing) - root pinning skipped");
        } else if (r.rootPinned) {
            d.add("Root of chain matches a known Google hardware attestation root ✓");
        } else {
            warnSignals++;
            d.add("Root of chain NOT in known Google set (new root or non-Google) ✗");
        }

        /* 3) 挑战值核对 */
        byte[] certChallenge = parseChallenge(extValue);
        if (certChallenge != null) {
            r.challengeMatch = Arrays.equals(certChallenge, challenge);
            if (r.challengeMatch) {
                d.add("attestationChallenge matches this run's nonce ✓");
            } else {
                status = DetectionResult.STATUS_DANGER;
                d.add("attestationChallenge MISMATCH - replayed/borrowed (canned) chain ✗");
            }
        } else {
            d.add("attestationChallenge not parseable (OEM format) - challenge check skipped");
        }

        /* 4) 安全级别（替换以往写死的 hardwareBacked=Yes） */
        r.securityLevel = parseAttestationSecurityLevel(extValue);
        String lvl = securityLevelName(r.securityLevel);
        d.add("attestationSecurityLevel: " + lvl);
        if (r.securityLevel == SEC_SOFTWARE) {
            warnSignals++;
            d.add("Software-level attestation - NOT hardware-backed ✗");
        } else if (r.securityLevel == SEC_TEE || r.securityLevel == SEC_STRONGBOX) {
            d.add("Hardware-backed (" + lvl + ") ✓");
        }

        /* 5) 吊销核对 */
        Set<String> revoked = loadRevocationSet(context);
        d.add("Revocation list: " + (sRevokedSource == null ? "unavailable" : sRevokedSource)
                + " (" + (revoked == null ? 0 : revoked.size()) + " entries)");
        String hitSerial = firstRevokedSerial(chain, revoked);
        if (hitSerial != null) {
            r.revoked = true;
            status = DetectionResult.STATUS_DANGER;
            d.add("Certificate REVOKED by Google (serial " + shortSerial(hitSerial) + ") - leaked/forged keybox ✗");
        } else if (revoked != null && !revoked.isEmpty()) {
            d.add("No chain certificate is in Google's revocation list ✓");
        }

        /* 6) attestationApplicationId 核对包名 */
        String pkg = context != null ? context.getPackageName() : null;
        Boolean appIdMatch = attestationAppIdContains(extValue, pkg);
        if (appIdMatch == null) {
            d.add("attestationApplicationId not present/parseable - app-binding check skipped");
        } else if (appIdMatch) {
            d.add("attestationApplicationId binds to this app (" + pkg + ") ✓");
        } else {
            warnSignals++;
            d.add("attestationApplicationId does NOT match this app - borrowed chain? ✗");
        }

        /* 判定：硬信号→DANGER；软信号累计；软件级+根未命中 一起 → 升级 DANGER（软件伪造硬件） */
        if (status != DetectionResult.STATUS_DANGER) {
            boolean softwareAndUnpinned = (r.securityLevel == SEC_SOFTWARE) && !r.rootPinned && roots != null && !roots.isEmpty();
            if (softwareAndUnpinned) {
                status = DetectionResult.STATUS_DANGER;
                d.add("Software-level attestation not chaining to Google root - fabricated hardware claim");
            } else if (warnSignals >= 1) {
                status = DetectionResult.STATUS_WARNING;
            }
        }

        r.trustStatus = status;
        r.trustSummary = status == DetectionResult.STATUS_DANGER
                ? "Attestation forged / revoked / replayed"
                : status == DetectionResult.STATUS_WARNING
                ? "Attestation weakly trusted (see details)"
                : "Attestation chain fully trusted (crypto + root + challenge + not revoked)";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Chain crypto helpers
    // ─────────────────────────────────────────────────────────────────────────

    /** 逐级 chain[i] 由 chain[i+1] 公钥验签；全部通过返回 true。 */
    private static boolean verifyChainLinks(Certificate[] chain) {
        try {
            for (int i = 0; i < chain.length - 1; i++) {
                chain[i].verify(chain[i + 1].getPublicKey());
            }
            /* 链末若自签，验其自身；不通过不算断链（末端可能不含根） */
            if (chain.length >= 1) {
                try { chain[chain.length - 1].verify(chain[chain.length - 1].getPublicKey()); } catch (Exception ignore) { }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** 链末公钥 == 某 Google 根公钥，或链末可被某 Google 根公钥验签。 */
    private static boolean isChainRootedInGoogle(Certificate[] chain, List<PublicKey> roots) {
        if (roots == null || roots.isEmpty() || chain.length == 0) return false;
        try {
            X509Certificate top = (X509Certificate) chain[chain.length - 1];
            byte[] topKey = top.getPublicKey().getEncoded();
            for (PublicKey rk : roots) {
                if (rk.getEncoded() != null && Arrays.equals(rk.getEncoded(), topKey)) return true;
                try { top.verify(rk); return true; } catch (Exception ignore) { }
            }
        } catch (Exception ignore) { }
        return false;
    }

    private static String firstRevokedSerial(Certificate[] chain, Set<String> revoked) {
        if (revoked == null || revoked.isEmpty()) return null;
        for (Certificate c : chain) {
            try {
                BigInteger sn = ((X509Certificate) c).getSerialNumber();
                if (sn == null) continue;
                String hex = sn.toString(16).toLowerCase(Locale.ROOT);
                if (revoked.contains(hex)) return hex;
                /* 兼容去零/补零边界 */
                String noLead = hex.replaceFirst("^0+", "");
                if (!noLead.equals(hex) && revoked.contains(noLead)) return noLead;
            } catch (Exception ignore) { }
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Data loaders: revocation set + Google roots (bundled asset + live refresh)
    // ─────────────────────────────────────────────────────────────────────────

    /** 吊销序列号集合（小写 hex）。优先联网拉最新，失败回落内置快照；进程内缓存。 */
    private static Set<String> loadRevocationSet(Context context) {
        Set<String> cached = sRevokedSerials;
        if (cached != null) return cached;
        synchronized (KeyAttestationHelper.class) {
            if (sRevokedSerials != null) return sRevokedSerials;
            Set<String> net = parseStatus(fetchUrl(STATUS_URL));
            if (net != null && !net.isEmpty()) {
                sRevokedSource = "network";
                sRevokedSerials = net;
                return net;
            }
            Set<String> asset = parseStatus(readAsset(context, ASSET_STATUS));
            if (asset != null) {
                sRevokedSource = "bundled";
                sRevokedSerials = asset;
                return asset;
            }
            sRevokedSource = "unavailable";
            sRevokedSerials = new HashSet<>();
            return sRevokedSerials;
        }
    }

    private static Set<String> parseStatus(String body) {
        if (body == null || body.isEmpty()) return null;
        try {
            JSONObject root = new JSONObject(body);
            JSONObject entries = root.optJSONObject("entries");
            if (entries == null) return null;
            Set<String> out = new HashSet<>(entries.length() * 2);
            Iterator<String> it = entries.keys();
            while (it.hasNext()) {
                String k = it.next();
                if (k != null && !k.isEmpty()) out.add(k.toLowerCase(Locale.ROOT));
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /** Google 硬件认证根公钥集合（内置快照）。进程内缓存。 */
    private static List<PublicKey> loadGoogleRootKeys(Context context) {
        List<PublicKey> cached = sGoogleRootKeys;
        if (cached != null) return cached;
        synchronized (KeyAttestationHelper.class) {
            if (sGoogleRootKeys != null) return sGoogleRootKeys;
            List<PublicKey> keys = new ArrayList<>();
            try {
                String body = readAsset(context, ASSET_ROOTS);
                if (body != null && !body.isEmpty()) {
                    JSONArray arr = new JSONArray(body);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    for (int i = 0; i < arr.length(); i++) {
                        String pem = arr.optString(i, "");
                        if (pem.isEmpty()) continue;
                        try {
                            X509Certificate c = (X509Certificate) cf.generateCertificate(
                                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
                            if (c != null) keys.add(c.getPublicKey());
                        } catch (Exception ignore) { }
                    }
                }
            } catch (Exception ignore) { }
            sGoogleRootKeys = keys;
            return keys;
        }
    }

    private static String fetchUrl(String urlStr) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(HTTP_TIMEOUT_MS);
            conn.setReadTimeout(HTTP_TIMEOUT_MS);
            int code = conn.getResponseCode();
            if (code != 200) return null;
            return readStream(conn.getInputStream());
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readAsset(Context context, String path) {
        if (context == null) return null;
        try (InputStream in = context.getAssets().open(path)) {
            return readStream(in);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readStream(InputStream in) {
        if (in == null) return null;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[8192];
            int r;
            while ((r = br.read(buf)) != -1) sb.append(buf, 0, r);
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String shortSerial(String hex) {
        return hex.length() > 16 ? hex.substring(0, 16) + "…" : hex;
    }

    private static String securityLevelName(int lvl) {
        switch (lvl) {
            case SEC_SOFTWARE: return "Software";
            case SEC_TEE: return "TrustedEnvironment";
            case SEC_STRONGBOX: return "StrongBox";
            default: return "Unknown";
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ASN.1 parsing: KeyDescription top-level fields
    // ─────────────────────────────────────────────────────────────────────────

    /** 取扩展 OCTET STRING 内层的 KeyDescription SEQUENCE。 */
    private static ASN1Sequence keyDescriptionOf(byte[] extValue) {
        try {
            ASN1Primitive outer = ASN1Primitive.fromByteArray(extValue);
            byte[] keyDescBytes;
            if (outer instanceof ASN1OctetString) keyDescBytes = ((ASN1OctetString) outer).getOctets();
            else if (outer instanceof DEROctetString) keyDescBytes = ((DEROctetString) outer).getOctets();
            else return null;
            ASN1Primitive p = ASN1Primitive.fromByteArray(keyDescBytes);
            return (p instanceof ASN1Sequence) ? (ASN1Sequence) p : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** KeyDescription 标准 schema：index 1 = attestationSecurityLevel (ENUMERATED)。 */
    private static int parseAttestationSecurityLevel(byte[] extValue) {
        ASN1Sequence kd = keyDescriptionOf(extValue);
        if (kd == null || kd.size() < 2) return -1;
        return getInt(kd.getObjectAt(1));
    }

    /** KeyDescription 标准 schema：index 4 = attestationChallenge (OCTET STRING)。 */
    private static byte[] parseChallenge(byte[] extValue) {
        ASN1Sequence kd = keyDescriptionOf(extValue);
        if (kd == null || kd.size() < 5) return null;
        return getOctetString(kd.getObjectAt(4));
    }

    /**
     * attestationApplicationId（softwareEnforced tag 709）内含调用方包名。
     * 为鲁棒起见：定位 index 6 (softwareEnforced) 的原始字节并在其中查找包名 ASCII 子串。
     * @return null 表示未找到/无法解析（跳过判定），否则表示是否含本包名。
     */
    private static Boolean attestationAppIdContains(byte[] extValue, String pkg) {
        if (pkg == null || pkg.isEmpty()) return null;
        ASN1Sequence kd = keyDescriptionOf(extValue);
        if (kd == null || kd.size() < 7) return null;
        try {
            byte[] sw = kd.getObjectAt(6).toASN1Primitive().getEncoded();
            byte[] needle = pkg.getBytes(StandardCharsets.US_ASCII);
            return indexOf(sw, needle) >= 0 ? Boolean.TRUE : Boolean.FALSE;
        } catch (Exception e) {
            return null;
        }
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        if (hay == null || needle == null || needle.length == 0 || hay.length < needle.length) return -1;
        outer:
        for (int i = 0; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /**
     * 解析 TEE 认证的机身标识与 OS 版本/补丁（供 System Property Integrity 做"属性 vs 硬件"交叉验证）。
     * 这些值由 TEE 附带、resetprop/Magisk 改不动，是识破彻底属性伪装的 ground truth。
     * AuthorizationList 里各项为 [tag] EXPLICIT：osVersion=705, osPatchLevel=706,
     * attestationIdBrand=710, Device=711, Product=712, Manufacturer=716, Model=717。
     */
    private static void parseDeviceIdentity(byte[] extValue, AttestationReport r) {
        ASN1Sequence kd = keyDescriptionOf(extValue);
        if (kd == null) return;
        for (int idx : new int[]{7, 6}) {   // teeEnforced 优先，softwareEnforced 兜底
            if (idx >= kd.size()) continue;
            ASN1Sequence al = toSequence(kd.getObjectAt(idx));
            if (al == null) continue;
            if (r.osVersion < 0)          r.osVersion = authInt(al, 705);
            if (r.osPatchLevel < 0)       r.osPatchLevel = authInt(al, 706);
            if (r.idBrand == null)        r.idBrand = authStr(al, 710);
            if (r.idDevice == null)       r.idDevice = authStr(al, 711);
            if (r.idProduct == null)      r.idProduct = authStr(al, 712);
            if (r.idManufacturer == null) r.idManufacturer = authStr(al, 716);
            if (r.idModel == null)        r.idModel = authStr(al, 717);
        }
    }

    private static ASN1Primitive authTag(ASN1Sequence authList, int tag) {
        if (authList == null) return null;
        for (int i = 0; i < authList.size(); i++) {
            ASN1Encodable e = authList.getObjectAt(i);
            if (e instanceof ASN1TaggedObject) {
                ASN1TaggedObject to = (ASN1TaggedObject) e;
                if (to.getTagNo() == tag) {
                    try { return to.getBaseObject().toASN1Primitive(); } catch (Exception ex) { return null; }
                }
            }
        }
        return null;
    }

    private static int authInt(ASN1Sequence al, int tag) {
        ASN1Primitive p = authTag(al, tag);
        return p == null ? -1 : getInt(p);
    }

    private static String authStr(ASN1Sequence al, int tag) {
        ASN1Primitive p = authTag(al, tag);
        byte[] b = (p == null) ? null : getOctetString(p);
        if (b == null || b.length == 0) return null;
        try { return new String(b, StandardCharsets.UTF_8).trim(); } catch (Exception e) { return null; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Misc
    // ─────────────────────────────────────────────────────────────────────────

    /** 生成带 attestation 挑战的 EC 密钥（刻意 PURPOSE_SIGN，规避 attest-key 空 KeyUsage 的 RFC 误报）。
     *  deviceProps=true 时附带设备属性认证(API31+：brand/device/product/manufacturer/model)。 */
    private static void generateAttestationKey(byte[] challenge, boolean deviceProps) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                ATTESTATION_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);
        if (deviceProps && Build.VERSION.SDK_INT >= 31) {
            b.setDevicePropertiesAttestationIncluded(true);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
        kpg.initialize(b.build());
        kpg.generateKeyPair();
    }

    private static boolean isLikelyEmulator() {
        String model = Build.MODEL != null ? Build.MODEL : "";
        String hardware = Build.HARDWARE != null ? Build.HARDWARE : "";
        String product = Build.PRODUCT != null ? Build.PRODUCT : "";
        String device = Build.DEVICE != null ? Build.DEVICE : "";
        String lower = (model + " " + hardware + " " + product + " " + device).toLowerCase();
        return lower.contains("emulator") || lower.contains("generic") || lower.contains("sdk")
                || lower.contains("goldfish") || lower.contains("ranchu") || lower.contains("vbox");
    }

    private static void deleteAttestationKey(KeyStore ks) {
        try {
            ks.deleteEntry(ATTESTATION_KEY_ALIAS);
        } catch (Exception ignored) {
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ASN.1 parsing: RootOfTrust (unchanged from prior implementation)
    // ─────────────────────────────────────────────────────────────────────────

    private static RootOfTrust parseRootOfTrust(byte[] extValue) {
        try {
            ASN1Primitive outer = ASN1Primitive.fromByteArray(extValue);
            byte[] keyDescBytes;
            if (outer instanceof ASN1OctetString) {
                keyDescBytes = ((ASN1OctetString) outer).getOctets();
            } else if (outer instanceof DEROctetString) {
                keyDescBytes = ((DEROctetString) outer).getOctets();
            } else {
                return null;
            }

            ASN1Primitive keyDescPrim = ASN1Primitive.fromByteArray(keyDescBytes);
            if (!(keyDescPrim instanceof ASN1Sequence)) {
                return null;
            }
            ASN1Sequence keyDesc = (ASN1Sequence) keyDescPrim;
            if (keyDesc.size() < 6) {
                return null;
            }

            for (int authListIdx : new int[]{7, 6, 8, 5}) {
                if (authListIdx >= keyDesc.size()) continue;
                RootOfTrust rot = parseRootOfTrustFromAuthList(toSequence(keyDesc.getObjectAt(authListIdx)));
                if (rot != null) return rot;
            }

            for (int i = 0; i < keyDesc.size(); i++) {
                RootOfTrust rot = searchRootOfTrustRecursive(keyDesc.getObjectAt(i), 0, 8);
                if (rot != null) return rot;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static RootOfTrust searchRootOfTrustRecursive(ASN1Encodable enc, int depth, int maxDepth) {
        if (depth >= maxDepth) return null;
        ASN1Sequence seq = toSequence(enc);
        if (seq == null) return null;
        RootOfTrust rot = parseRootOfTrustFromAuthList(seq);
        if (rot != null) return rot;
        for (int i = 0; i < seq.size(); i++) {
            rot = searchRootOfTrustRecursive(seq.getObjectAt(i), depth + 1, maxDepth);
            if (rot != null) return rot;
        }
        return null;
    }

    private static RootOfTrust parseRootOfTrustFromAuthList(ASN1Sequence authList) {
        if (authList == null) return null;
        for (int i = 0; i < authList.size(); i++) {
            ASN1Encodable entryEnc = authList.getObjectAt(i);
            ASN1Sequence rootSeq = null;

            if (entryEnc instanceof ASN1TaggedObject) {
                ASN1TaggedObject to = (ASN1TaggedObject) entryEnc;
                if (to.getTagNo() == KM_TAG_ROOT_OF_TRUST) {
                    rootSeq = toSequence(to.getBaseObject());
                }
            }
            if (rootSeq == null) {
                ASN1Sequence entry = toSequence(entryEnc);
                if (entry != null) {
                    if (entry.size() >= 2) {
                        int tag = getTagValue(entry.getObjectAt(0));
                        if (tag == KM_TAG_ROOT_OF_TRUST) {
                            rootSeq = toSequence(entry.getObjectAt(1));
                        }
                    }
                    if (rootSeq == null && (entry.size() == 4 || entry.size() == 3)) {
                        rootSeq = entry;
                    }
                }
            }
            if (rootSeq == null || rootSeq.size() < 3) continue;

            RootOfTrust rot = parseRootOfTrustSequence(rootSeq);
            if (rot != null) return rot;
        }
        return null;
    }

    private static RootOfTrust parseRootOfTrustSequence(ASN1Sequence rootSeq) {
        try {
            byte[] verifiedBootKey = getOctetString(rootSeq.getObjectAt(0));
            boolean deviceLocked = getBoolean(rootSeq.getObjectAt(1));
            int verifiedBootState = getInt(rootSeq.getObjectAt(2));
            byte[] verifiedBootHash = rootSeq.size() >= 4 ? getOctetString(rootSeq.getObjectAt(3)) : null;

            if (verifiedBootKey == null && verifiedBootHash == null) return null;

            String vbkHex = verifiedBootKey != null ? bytesToHex(verifiedBootKey) : "(null)";
            String vbhHex = verifiedBootHash != null ? bytesToHex(verifiedBootHash) : "(null)";
            boolean allZeros = isAllZeros(verifiedBootKey);

            String stateName;
            switch (verifiedBootState) {
                case BOOT_VERIFIED:   stateName = "Verified"; break;
                case BOOT_SELF_SIGNED: stateName = "SelfSigned"; break;
                case BOOT_UNVERIFIED: stateName = "Unverified"; break;
                case BOOT_FAILED:     stateName = "Failed"; break;
                default:              stateName = "Unknown"; break;
            }

            return new RootOfTrust(vbkHex, deviceLocked, verifiedBootState, stateName, vbhHex, allZeros);
        } catch (Exception e) {
            return null;
        }
    }

    private static ASN1Sequence toSequence(ASN1Encodable e) {
        if (e == null) return null;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            return p instanceof ASN1Sequence ? (ASN1Sequence) p : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static int getTagValue(ASN1Encodable e) {
        if (e == null) return -1;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof org.bouncycastle.asn1.ASN1Integer) {
                return ((org.bouncycastle.asn1.ASN1Integer) p).getValue().intValue();
            }
        } catch (Exception ex) {
            // ignore
        }
        return -1;
    }

    private static byte[] getOctetString(ASN1Encodable e) {
        if (e == null) return null;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof ASN1OctetString) {
                return ((ASN1OctetString) p).getOctets();
            }
            if (p instanceof ASN1TaggedObject) {
                Object inner = ((ASN1TaggedObject) p).getBaseObject();
                if (inner instanceof ASN1OctetString) {
                    return ((ASN1OctetString) inner).getOctets();
                }
            }
        } catch (Exception ex) {
            // ignore
        }
        return null;
    }

    private static boolean getBoolean(ASN1Encodable e) {
        if (e == null) return false;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof org.bouncycastle.asn1.ASN1Boolean) {
                return ((org.bouncycastle.asn1.ASN1Boolean) p).isTrue();
            }
        } catch (Exception ex) {
            // ignore
        }
        return false;
    }

    private static int getInt(ASN1Encodable e) {
        if (e == null) return -1;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof org.bouncycastle.asn1.ASN1Integer) {
                return ((org.bouncycastle.asn1.ASN1Integer) p).getValue().intValue();
            }
            if (p instanceof org.bouncycastle.asn1.ASN1Enumerated) {
                return ((org.bouncycastle.asn1.ASN1Enumerated) p).getValue().intValue();
            }
        } catch (Exception ex) {
            // ignore
        }
        return -1;
    }

    private static boolean isAllZeros(byte[] b) {
        if (b == null || b.length == 0) return true;
        for (byte x : b) {
            if (x != 0) return false;
        }
        return true;
    }

    private static String bytesToHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format(Locale.US, "%02x", x & 0xff));
        }
        return sb.toString();
    }

    private static class RootOfTrust {
        final String verifiedBootKeyHex;
        final boolean deviceLocked;
        final int verifiedBootState;
        final String verifiedBootStateName;
        final String verifiedBootHashHex;
        final boolean verifiedBootKeyAllZeros;

        RootOfTrust(String verifiedBootKeyHex, boolean deviceLocked, int verifiedBootState,
                    String verifiedBootStateName, String verifiedBootHashHex, boolean verifiedBootKeyAllZeros) {
            this.verifiedBootKeyHex = verifiedBootKeyHex;
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
            this.verifiedBootStateName = verifiedBootStateName;
            this.verifiedBootHashHex = verifiedBootHashHex;
            this.verifiedBootKeyAllZeros = verifiedBootKeyAllZeros;
        }
    }
}

package anti.rusda.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 手机环境检测：Root、Bootloader、模拟器、SELinux、多开、可疑文件、应用是否可调试等。
 * 依赖 libenvdetect.so（可选 JNI 接口，当前主要为 Java 实现）。
 */
public class EnvDetectionManager {

    static {
        try {
            System.loadLibrary("envdetect");
        } catch (Throwable ignored) { }
    }

    @SuppressWarnings("unused")
    private static native String nativeGetEnvVersion();

    private static final String[] SUSPICIOUS_PATHS = {
            "/data/local/tmp/frida",
            "/data/local/tmp/frida-server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/data/app/frida",
            "/debug_ramdisk"
    };

    private final Context context;

    public EnvDetectionManager(Context context) {
        this.context = context;
    }

    public List<DetectionResult> runAllDetections() {
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectBootloader());
        results.add(detectRoot());
        results.add(detectSuspiciousFiles());
        results.add(detectEmulator());
        results.add(detectSELinuxStatus());
        results.add(detectAppDebuggable());
        results.add(checkProcessStatus());
        return results;
    }

    private DetectionResult detectBootloader() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        String state = getSystemProperty("ro.boot.verifiedbootstate", "");
        String flashLocked = getSystemProperty("ro.boot.flash.locked", "");
        String vbMeta = getSystemProperty("ro.boot.veritymode", "");

        details.add("ro.boot.verifiedbootstate: " + (state.isEmpty() ? "(empty)" : state));
        details.add("ro.boot.flash.locked: " + (flashLocked.isEmpty() ? "(empty)" : flashLocked));

        if ("orange".equalsIgnoreCase(state) || "orange".equalsIgnoreCase(flashLocked)) {
            details.add("Bootloader appears unlocked (orange state)");
            status = DetectionResult.STATUS_WARNING;
        } else if ("0".equals(flashLocked) || "unlocked".equalsIgnoreCase(state)) {
            details.add("Bootloader may be unlocked");
            status = DetectionResult.STATUS_WARNING;
        } else if ("green".equalsIgnoreCase(state) || "1".equals(flashLocked) || "locked".equalsIgnoreCase(state)) {
            details.add("Bootloader appears locked");
        } else if (state.isEmpty() && flashLocked.isEmpty()) {
            details.add("Could not determine bootloader state (no prop access)");
        }

        return new DetectionResult(
                "Bootloader",
                status == DetectionResult.STATUS_NORMAL ? "Bootloader locked or unknown" : "Bootloader may be unlocked",
                status,
                details
        );
    }

    private static String getSystemProperty(String key, String def) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            Method get = c.getMethod("get", String.class, String.class);
            return (String) get.invoke(null, key, def);
        } catch (Throwable e) {
            return def;
        }
    }

    private DetectionResult detectRoot() {
        List<String> indicators = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        String[] rootIndicators = {
                "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
                "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
                "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
                "/magisk/.core/bin/su", "/system/sbin/su"
        };
        for (String path : rootIndicators) {
            if (new File(path).exists()) {
                indicators.add("Found: " + path);
                status = DetectionResult.STATUS_WARNING;
            }
        }
        if (new File("/data/adb/magisk").exists()) {
            indicators.add("Magisk directory detected");
            status = DetectionResult.STATUS_WARNING;
        }
        DetectionResult result = new DetectionResult(
                "Root",
                indicators.isEmpty() ? "Device appears unrooted" : indicators.size() + " root indicator(s) found",
                status
        );
        result.setDetails(indicators.isEmpty() ? Collections.singletonList("No root binaries or Magisk detected") : indicators);
        return result;
    }

    private DetectionResult detectSuspiciousFiles() {
        List<String> findings = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        for (String path : SUSPICIOUS_PATHS) {
            if (new File(path).exists()) {
                findings.add("Found: " + path);
                status = DetectionResult.STATUS_DANGER;
            }
        }
        DetectionResult result = new DetectionResult(
                "Suspicious Files",
                findings.isEmpty() ? "No suspicious files detected" : findings.size() + " suspicious file(s) detected",
                status
        );
        result.setDetails(findings.isEmpty() ? Collections.singletonList("No Frida-related files found") : findings);
        return result;
    }

    private DetectionResult detectEmulator() {
        List<String> indicators = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        String[] emulatorIndicators = {
                "generic", "unknown", "google_sdk", "sdk", "sdk_x86", "vbox86p",
                "emulator", "simulator", "ranchu", "goldfish"
        };
        String hardware = Build.HARDWARE.toLowerCase();
        String product = Build.PRODUCT.toLowerCase();
        String device = Build.DEVICE.toLowerCase();
        String brand = Build.BRAND.toLowerCase();
        for (String indicator : emulatorIndicators) {
            if (hardware.contains(indicator) || product.contains(indicator) || device.contains(indicator) || brand.contains(indicator)) {
                indicators.add("Indicator in build: " + indicator);
                status = DetectionResult.STATUS_WARNING;
            }
        }
        String[] emulatorFiles = {
                "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props"
        };
        for (String file : emulatorFiles) {
            if (new File(file).exists()) {
                indicators.add("Emulator file: " + file);
                status = DetectionResult.STATUS_WARNING;
            }
        }
        if (new File("/data/misc/emu/update_check.cfg").exists()) {
            indicators.add("BlueStacks configuration detected");
            status = DetectionResult.STATUS_WARNING;
        }
        DetectionResult result = new DetectionResult(
                "Emulator",
                indicators.isEmpty() ? "Running on physical device" : indicators.size() + " emulator indicator(s) found",
                status
        );
        result.setDetails(indicators.isEmpty() ? Collections.singletonList("Device appears to be physical") : indicators);
        return result;
    }

    private DetectionResult detectSELinuxStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            String selinuxContent = readFileContent("/sys/fs/selinux/enforce");
            int enforceMode = Integer.parseInt(selinuxContent.trim());
            if (enforceMode == 0) {
                details.add("SELinux is in permissive mode");
                status = DetectionResult.STATUS_WARNING;
            } else {
                details.add("SELinux is enforcing");
            }
        } catch (Exception e) {
            details.add("Could not determine SELinux status: " + e.getMessage());
        }
        return new DetectionResult(
                "SELinux",
                status == DetectionResult.STATUS_NORMAL ? "SELinux is enforcing" : "SELinux is permissive",
                status,
                details
        );
    }

    private DetectionResult detectAppDebuggable() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        if (context != null) {
            try {
                ApplicationInfo appInfo = context.getApplicationInfo();
                boolean isDebuggable = (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                if (isDebuggable) {
                    details.add("App is marked as debuggable");
                    status = DetectionResult.STATUS_WARNING;
                } else {
                    details.add("App is not debuggable");
                }
            } catch (Exception e) {
                details.add("Could not check debuggable flag");
            }
        }
        return new DetectionResult(
                "App Debuggable",
                status == DetectionResult.STATUS_NORMAL ? "App not debuggable" : "App is debuggable",
                status,
                details
        );
    }

    private DetectionResult checkProcessStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            details.add("Process ID: " + Process.myPid());
            if (context != null) {
                String packageName = context.getPackageName();
                details.add("Package: " + packageName);
                if (packageName != null && (packageName.contains(":") || packageName.toLowerCase().contains("dual"))) {
                    details.add("Package name suggests dual app");
                    status = DetectionResult.STATUS_WARNING;
                }
                if (context.getFilesDir() != null) {
                    String dataDir = context.getFilesDir().getAbsolutePath();
                    details.add("Files dir: " + dataDir);
                    if (dataDir.contains("parallel") || dataDir.contains("dual") || dataDir.contains("clone") || dataDir.contains("multi")) {
                        details.add("Suspicious data directory path");
                        status = DetectionResult.STATUS_WARNING;
                    }
                }
            }
        } catch (Exception e) {
            details.add("Error: " + e.getMessage());
        }
        return new DetectionResult(
                "Multi-instance",
                status == DetectionResult.STATUS_NORMAL ? "No multi-instance detected" : "Multi-instance app detected",
                status,
                details
        );
    }

    private static String readFileContent(String path) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
}

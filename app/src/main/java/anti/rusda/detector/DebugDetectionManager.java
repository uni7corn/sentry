package anti.rusda.detector;

import android.content.Context;
import android.os.Debug;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 调试相关检测：Frida、Xposed、IDA/ptrace 附加、端口等。
 * 依赖 libantidebug.so（端口扫描在 Native 层）。
 */
public class DebugDetectionManager {

    /** Frida 线程检测在 Native 层（syscall），防 Hook */
    private static native String[] nativeDetectFridaThreads();
    /** 端口扫描在 Native 层（syscall），结果由此方法返回 */
    private static native String[] nativeGetFridaPortScanResult();
    /** 内存签名扫描在 Native 层（syscall），防 Hook */
    private static native String[] nativeGetMemorySignatureResult();
    /** Native Hook 检测（内联/PLT/GOT），增强 Xposed 检测 */
    private static native String[] nativeDetectHook();

    public static void ensureNativeLoaded() {
        try {
            System.loadLibrary("antidebug");
        } catch (Throwable ignored) { }
    }

    public List<DetectionResult> runAllDetections() {
        ensureNativeLoaded();
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectFridaThreads());
        results.add(detectFridaPorts());
        results.add(detectMemorySignatures());
        results.add(detectNamedPipes());
        results.add(detectPtraceStatus());
        results.add(detectDebuggerAttached());
        results.add(checkLibraryIntegrity());
        return results;
    }

    /** Native 实现（syscall），防 Java 层 Hook */
    private DetectionResult detectFridaThreads() {
        String[] raw = nativeDetectFridaThreads();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Frida Threads", "Scan failed", DetectionResult.STATUS_WARNING);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Frida Threads", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectFridaPorts() {
        String[] raw = nativeGetFridaPortScanResult();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Frida Ports", "Scan failed", DetectionResult.STATUS_WARNING);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Frida Ports", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectMemorySignatures() {
        String[] raw = nativeGetMemorySignatureResult();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Memory Signatures", "Scan failed", DetectionResult.STATUS_WARNING);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Memory Signatures", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectNamedPipes() {
        List<String> pipes = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            String unixContent = readFileContent("/proc/self/net/unix");
            for (String line : unixContent.split("\\n")) {
                if (line.toLowerCase().contains("frida") || line.toLowerCase().contains("gmain") || line.toLowerCase().contains("gdbus")) {
                    pipes.add(line.trim());
                    status = DetectionResult.STATUS_DANGER;
                }
            }
        } catch (Exception e) {
            pipes.add("Error checking pipes: " + e.getMessage());
        }
        DetectionResult result = new DetectionResult(
                "Named Pipes",
                pipes.isEmpty() ? "No suspicious pipes detected" : pipes.size() + " suspicious pipe(s) detected",
                status
        );
        result.setDetails(pipes.isEmpty() ? Collections.singletonList("No Frida-related named pipes found") : pipes);
        return result;
    }

    private DetectionResult detectPtraceStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            String statusContent = readFileContent("/proc/self/status");
            for (String line : statusContent.split("\\n")) {
                if (line.startsWith("TracerPid:")) {
                    String value = line.substring(line.indexOf(":") + 1).trim();
                    int tracerPid = Integer.parseInt(value);
                    if (tracerPid != 0) {
                        details.add("Process is being traced by PID: " + tracerPid);
                        status = DetectionResult.STATUS_DANGER;
                    } else {
                        details.add("No tracer process detected (TracerPid: 0)");
                    }
                }
                if (line.startsWith("State:")) {
                    details.add("Process state: " + line.substring(line.indexOf(":") + 1).trim());
                }
            }
        } catch (Exception e) {
            details.add("Error reading process status: " + e.getMessage());
        }
        return new DetectionResult(
                "Ptrace / IDA Attach",
                status == DetectionResult.STATUS_NORMAL ? "Process is not being traced" : "Process is being traced!",
                status,
                details
        );
    }

    private DetectionResult detectDebuggerAttached() {
        boolean isDebug = Debug.isDebuggerConnected();
        List<String> details = new ArrayList<>();
        details.add(isDebug ? "Debugger is currently connected" : "No debugger detected");
        int status = isDebug ? DetectionResult.STATUS_DANGER : DetectionResult.STATUS_NORMAL;
        return new DetectionResult(
                "Debugger Attached",
                status == DetectionResult.STATUS_NORMAL ? "No debugger detected" : "Debugger detected",
                status,
                details
        );
    }

    /** Java 反射 + Native 内联/PLT 检测，双重验证 */
    private DetectionResult checkLibraryIntegrity() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        /* 1. Java: XposedBridge 类检测 */
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            details.add("Xposed framework detected (Class.forName)");
            status = DetectionResult.STATUS_DANGER;
        } catch (ClassNotFoundException e) {
            details.add("Xposed framework not detected (Class.forName)");
        }

        /* 2. Native: 内联 Hook、PLT/GOT、libc 完整性 */
        String[] hookRaw = nativeDetectHook();
        if (hookRaw != null && hookRaw.length >= 2) {
            try {
                int hookStatus = Integer.parseInt(hookRaw[0]);
                if (hookStatus == DetectionResult.STATUS_DANGER) {
                    details.add(hookRaw.length > 2 ? hookRaw[2] : "Native hook/integrity check failed");
                    status = DetectionResult.STATUS_DANGER;
                }
            } catch (NumberFormatException ignored) { }
        }

        return new DetectionResult(
                "Xposed / Hook Framework",
                status == DetectionResult.STATUS_NORMAL ? "No Xposed detected" : "Framework modification detected",
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

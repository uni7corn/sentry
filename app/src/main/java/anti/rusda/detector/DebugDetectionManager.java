package anti.rusda.detector;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Debug;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
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
    /** 内存签名扫描在 Native 层（syscall），防 Hook；advancedChecks=true 时匿名可执行内存阈值 4KB */
    private static native String[] nativeGetMemorySignatureResult(boolean advancedChecks);
    /** Native Hook 检测（内联/PLT/GOT），增强 Xposed 检测 */
    private static native String[] nativeDetectHook();
    /** Native Xposed 特征路径与 /proc/self/fd（linjector 等）检测 */
    private static native String[] nativeDetectXposedPaths();
    /** Zygisk 注入检测（Smaps Private_Dirty + VMap + Pagemap），实现位于 libenvdetect */
    private static native String[] nativeDetectZygiskInjection();
    /** SO 代码段完整性（libc .text 内存 vs 磁盘 CRC32/比对），独立检测项 */
    private static native String[] nativeGetSoIntegrityResult();
    /** ArtMethod 入口检测：目标类关键方法 entry_point 是否在 libart/oat 外 */
    private static native String[] nativeGetArtMethodCheckResult(Class<?> targetClass);
    /** Hook 陷阱检测（SIGTRAP 是否被本进程 handler 捕获） */
    private static native String[] nativeGetTrapCheckResult();
    /** ClassLinker class_loaders_ 链表节点计数（ART 内存扫）；返回 int[3]={count, clOff, listOff}，count<0 表示扫描失败 */
    private static native int[] nativeDetectClassLoaderCount();

    public static void ensureNativeLoaded() {
        try {
            System.loadLibrary("antidebug");
        } catch (Throwable ignored) { }
        try {
            System.loadLibrary("envdetect");
        } catch (Throwable ignored) { }
    }

    /** 无 Context 时应用列表检测不执行；建议使用 {@link #runAllDetections(Context)}。 */
    public List<DetectionResult> runAllDetections() {
        return runAllDetections(null);
    }

    public List<DetectionResult> runAllDetections(Context context) {
        ensureNativeLoaded();
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectFridaThreads());
        results.add(detectFridaPorts());
        results.add(detectMemorySignatures(context));
        results.add(detectMapsViaExec());
        results.add(detectPtraceStatus());
        results.add(detectDebuggerAttached());
        results.add(checkLibraryIntegrity(context));
        results.add(detectSoIntegrity());
        results.add(detectArtMethodEntry());
        results.add(detectTrapCheck());
        results.add(detectZygiskInjection());
        return results;
    }

    /** Native 实现（syscall），防 Java 层 Hook */
    private DetectionResult detectFridaThreads() {
        String[] raw = nativeDetectFridaThreads();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Frida Threads", "Check skipped", DetectionResult.STATUS_NORMAL);
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
            return new DetectionResult("Frida Ports", "Check skipped", DetectionResult.STATUS_NORMAL);
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

    private DetectionResult detectMemorySignatures(Context context) {
        boolean advancedChecks = false;
        if (context != null) {
            SharedPreferences prefs = context.getSharedPreferences("sentry_prefs", Context.MODE_PRIVATE);
            advancedChecks = prefs.getBoolean("advanced_checks", false);
        }
        String[] raw = nativeGetMemorySignatureResult(advancedChecks);
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Memory Signatures", "Check skipped", DetectionResult.STATUS_NORMAL);
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

    /** SO 代码段完整性（libc .text 内存 vs 磁盘 CRC32/比对）。 */
    private DetectionResult detectSoIntegrity() {
        String[] raw = nativeGetSoIntegrityResult();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("SO Code Integrity", "Check skipped", DetectionResult.STATUS_NORMAL);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Collections.singletonList(raw[2])
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("SO Code Integrity", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectArtMethodEntry() {
        Class<?> activityClass;
        try {
            activityClass = Class.forName("android.app.Activity");
        } catch (ClassNotFoundException e) {
            return new DetectionResult("ArtMethod Entry", "Check skipped", DetectionResult.STATUS_NORMAL);
        }
        String[] raw = nativeGetArtMethodCheckResult(activityClass);
        if (raw == null || raw.length < 2) {
            return new DetectionResult("ArtMethod Entry", "Check skipped", DetectionResult.STATUS_NORMAL);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2 && raw[2] != null && !raw[2].isEmpty()
                ? Collections.singletonList(raw[2])
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("ArtMethod Entry", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectTrapCheck() {
        String[] raw = nativeGetTrapCheckResult();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Hook Trap", "Check skipped", DetectionResult.STATUS_NORMAL);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Collections.singletonList(raw[2])
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Hook Trap", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectZygiskInjection() {
        String[] raw = nativeDetectZygiskInjection();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Dirty Page / Memory Injection", "Check skipped", DetectionResult.STATUS_NORMAL);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Dirty Page / Memory Injection", summary, status);
        result.setDetails(details);
        return result;
    }

    /** 与 Native memory_scanner 一致的 maps 可疑模块签名（小写，做不区分大小写匹配）；含 QuickJS/frida-java-bridge/linjector */
    private static final String[] MAPS_SUSPICIOUS_SIGNATURES = {
            "frida", "gum-js", "gumjs", "gthread", "gobject", "gmain", "gdbus",
            "frida-agent", "frida-gadget", "frida-server", "frida-java-bridge", "linjector",
            "quickjs", "libquickjs",
            "liblspd.so", "libriru.so", "libriruloader.so",
            "libxposed", "xposed_art", "xposed_bridge", "xposedbridge", "xposedhelpers",
            "xposed.installer", "xposedbridge.jar", "de.robv.android.xposed",
            "org.lsposed", "zygisk_lsposed", "zygisk"
    };

    /**
     * 通过多种方式读取 maps：先尝试 FileReader 直接读，再尝试 exec("cat ...")，与 Native syscall 形成多通道。
     * 逐行检查是否包含可疑模块签名，与 memory_scanner 的签名列表一致。
     */
    private DetectionResult detectMapsViaExec() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        String summary = null;
        String mapsPath = "/proc/" + Process.myPid() + "/maps";
        BufferedReader reader = null;
        java.lang.Process process = null;
        try {
            /* 先尝试 FileReader（部分环境更稳定），失败再 exec */
            try {
                reader = new BufferedReader(new FileReader(mapsPath));
            } catch (Throwable ignored) {
                process = Runtime.getRuntime().exec(new String[]{"/system/bin/cat", mapsPath});
                reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            }
            String line;
            final int maxFindings = 16;
            int count = 0;
            while ((line = reader.readLine()) != null && count < maxFindings) {
                String lineLower = line.toLowerCase();
                for (String sig : MAPS_SUSPICIOUS_SIGNATURES) {
                    if (lineLower.contains(sig)) {
                        details.add(line.trim());
                        status = DetectionResult.STATUS_DANGER;
                        count++;
                        break;
                    }
                }
            }
            if (status == DetectionResult.STATUS_NORMAL) {
                details.add("No suspicious modules in maps (Java exec path)");
            }
            if (process != null) {
                process.waitFor();
            }
        } catch (IOException e) {
            details.add("Could not read maps (exec failed or permission denied)");
            summary = "Check skipped";
            status = DetectionResult.STATUS_NORMAL;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            details.add("Could not read maps (exec failed or permission denied)");
            summary = "Check skipped";
            status = DetectionResult.STATUS_NORMAL;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) { }
            }
            if (process != null) {
                process.destroy();
            }
        }
        if (summary == null) {
            summary = status == DetectionResult.STATUS_NORMAL
                    ? "Maps clean (Java exec)"
                    : (details.size() + " suspicious mapping(s) in maps (Java exec)");
        }
        return new DetectionResult("Maps detection (Java exec)", summary, status, details);
    }

    private DetectionResult detectPtraceStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        String summary;
        try {
            String statusContent = readProcFileWithFallback("/proc/self/status");  /* FileReader + exec 双通道 */
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
            summary = status == DetectionResult.STATUS_NORMAL ? "Process is not being traced" : "Process is being traced!";
        } catch (Exception e) {
            summary = "Check skipped";
            details.add("Could not read /proc/self/status (permission or I/O error)");
        }
        return new DetectionResult("Ptrace / IDA Attach", summary, status, details);
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

    /** Java 多维度检测 + Native 内联/PLT/路径 检测。不检测「应用安装」：安装 LSPosed Manager ≠ 当前进程被 hook。 */
    private DetectionResult checkLibraryIntegrity(Context context) {
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

        /* 2. Java: 堆栈检测 — 自造异常检查堆栈中是否包含 Xposed 特征类 */
        if (status != DetectionResult.STATUS_DANGER && detectXposedInStack()) {
            details.add("Xposed framework detected (stack trace)");
            status = DetectionResult.STATUS_DANGER;
        }

        /* 3. Java: 反射检测 XposedHelpers / findAndHookMethod */
        if (status != DetectionResult.STATUS_DANGER && detectXposedByReflection(details)) {
            status = DetectionResult.STATUS_DANGER;
        }

        /* 4. Java: ClassLoader 实例检测（LSPosed InMemoryClassLoader、LspModuleClassLoader）— 检测当前进程是否被 hook，非「应用安装」 */
        if (status != DetectionResult.STATUS_DANGER) {
            List<String> classloaderDetails = detectSuspiciousClassLoaders();
            if (!classloaderDetails.isEmpty()) {
                details.addAll(classloaderDetails);
                status = DetectionResult.STATUS_DANGER;
            }
        }

        /* 5. Native: Xposed 特征路径与 fd（linjector 等） */
        String[] pathRaw = nativeDetectXposedPaths();
        if (pathRaw != null && pathRaw.length >= 2) {
            try {
                if (Integer.parseInt(pathRaw[0]) == DetectionResult.STATUS_DANGER) {
                    for (int i = 2; i < pathRaw.length; i++) {
                        details.add(pathRaw[i]);
                    }
                    status = DetectionResult.STATUS_DANGER;
                }
            } catch (NumberFormatException ignored) { }
        }

        /* 6. Native: 内联 Hook、PLT/GOT、libc 完整性 */
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

        /* 7. Native: ClassLinker class_loaders_ 链表计数（ART 内存扫，GC 硬约束）。
         *
         * 原理：LSPosed 必须把模块 ClassLoader 挂在 ClassLinker::class_loaders_ 链上，
         * 否则 GC 回收 → 模块失效。这是 GC 模型决定的硬约束，Shamiko 这类 Hook
         * 系统查询接口的隐藏手段挡不住——我们直接读 C++ 堆内存里的链表。
         *
         * 误报控制（关键）：
         *  - 计数本身只作辅助证据，绝不单独定 DANGER（微信/手淘/银行 App 等用
         *    多层 ClassLoader 的合法应用计数本就偏高）。这里检测的是 Sentry 自身
         *    进程，结构简单，baseline 实测见 doc/DETECTION_SPEC.md。
         *  - 仅当计数显著超过校准阈值（CL_COUNT_DANGER）时，才作为独立强信号；
         *    中间区间只记录详情，不扣分。
         *  - 已被其他通道判 DANGER 时，高计数仅佐证。
         *  - 扫描失败（ART 版本/布局漂移）返回 <0，fail-safe 跳过，不影响结论。 */
        try {
            int[] clRes = nativeDetectClassLoaderCount();
            if (clRes != null && clRes.length >= 1) {
                int clCount = clRes[0];
                if (clCount < 0) {
                    details.add("ClassLinker scan unavailable (ART layout/version)");
                } else {
                    details.add("ClassLinker class_loaders_ count: " + clCount
                            + " (offsets cl=0x" + Integer.toHexString(clRes.length > 1 ? clRes[1] : 0)
                            + " list=0x" + Integer.toHexString(clRes.length > 2 ? clRes[2] : 0) + ")");
                    if (clCount >= CL_COUNT_DANGER) {
                        details.add("Abnormally high ClassLoader count (>= " + CL_COUNT_DANGER
                                + ") - strong LSPosed/injection indicator");
                        status = DetectionResult.STATUS_DANGER;
                    } else if (clCount >= CL_COUNT_NOTICE && status == DetectionResult.STATUS_DANGER) {
                        details.add("Elevated ClassLoader count corroborates framework injection");
                    }
                }
            }
        } catch (Throwable t) {
            /* native 调用异常时不影响其它通道结论 */
            details.add("ClassLinker scan error: "
                    + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName()));
        }

        return new DetectionResult(
                "Xposed / Hook Framework",
                status == DetectionResult.STATUS_NORMAL ? "No Xposed detected" : "Framework modification detected",
                status,
                details
        );
    }

    /* ClassLinker class_loaders_ 计数阈值（针对 Sentry 自身这种简单进程校准）。
     * CL_COUNT_DANGER：超过此值视为强注入信号 → 独立判 DANGER。
     * CL_COUNT_NOTICE：超过此值时若已 DANGER 则补一条佐证详情（永不独立扣分）。
     *
     * 校准依据（均 Pixel 6 Pro / Android 16 实测，fresh-process 各 3 次稳定取值，
     * 详见 doc/DETECTION_SPEC.md D7）：
     *   - 干净环境 baseline                 = 3
     *   - 活跃注入环境（frida + libart 被改）= 12
     *   - 原文另测 LSPosed 注入             = 13-15
     *   综合：干净 ≤5、注入 ≥12，安全间隔约 [6,11]。
     *   DANGER=9 取间隔中部（高出干净上限 4、低于注入下限 3，双侧留余量）：既不
     *   误伤干净设备（本工具第一优先级），又能稳抓注入（注入值降到 9-11 仍命中）。
     * 兜底：D7 还有 inline/PLT/GOT/ClassLoader 实例等多条通道，注入即使绕过本计数
     *   也会被其它通道抓住，故此处取偏保守阈值优先压低误报。
     * 注意：常量基于"被检测进程是 Sentry 自身（结构简单）"校准；注入值受加载模块
     *   数影响，移植到多 ClassLoader 宿主 App 必须重新测定 baseline 与阈值。 */
    private static final int CL_COUNT_DANGER = 9;
    private static final int CL_COUNT_NOTICE = 7;

    /** 通过自造异常检查堆栈中是否包含 Xposed 特征类名 */
    private static boolean detectXposedInStack() {
        try {
            throw new RuntimeException("xposed_stack_check");
        } catch (Throwable t) {
            for (StackTraceElement e : t.getStackTrace()) {
                String cn = e.getClassName();
                if (cn != null && (cn.contains("de.robv.android.xposed.XposedBridge")
                        || cn.contains("de.robv.android.xposed.XposedHelpers")
                        || cn.contains("org.lsposed"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 反射检测 XposedHelpers / XposedBridge 中的 findAndHookMethod 等关键方法是否存在 */
    private static boolean detectXposedByReflection(List<String> details) {
        String[] classesToCheck = {
                "de.robv.android.xposed.XposedHelpers",
                "de.robv.android.xposed.XposedBridge"
        };
        String[] methodsToCheck = { "findAndHookMethod", "hookAllMethods" };
        for (String className : classesToCheck) {
            try {
                Class<?> c = Class.forName(className);
                for (String methodName : methodsToCheck) {
                    for (Method m : c.getDeclaredMethods()) {
                        if (methodName.equals(m.getName())) {
                            if (details != null) {
                                details.add("Xposed API present: " + className + "." + methodName);
                            }
                            return true;
                        }
                    }
                }
            } catch (ClassNotFoundException ignored) {
                // 该类不存在，继续检查下一个
            } catch (Throwable t) {
                if (details != null) {
                    details.add("Reflection check exception: " + t.getMessage());
                }
                return true; // 反射异常可能为环境篡改
            }
        }
        return false;
    }

    /**
     * 检测可疑的 ClassLoader 实例（LSPosed InMemoryClassLoader、LspModuleClassLoader、XposedBridge）。
     * 需绕过 Hidden API 限制（VMDebug.getInstancesOfClasses）。
     */
    private static List<String> detectSuspiciousClassLoaders() {
        List<String> findings = new ArrayList<>();
        try {
            bypassHiddenApiRestrictions();
            Class<?> vmDebugClass = Class.forName("dalvik.system.VMDebug");
            Method getInstancesMethod = vmDebugClass.getDeclaredMethod(
                    "getInstancesOfClasses", Class[].class, boolean.class);
            getInstancesMethod.setAccessible(true);

            Class<?>[] classes = {ClassLoader.class};
            Object[][] instances = (Object[][]) getInstancesMethod.invoke(null, classes, false);

            if (instances == null || instances.length == 0) return findings;

            for (Object obj : instances[0]) {
                if (obj == null) continue;
                ClassLoader cl = (ClassLoader) obj;
                String clName = cl.getClass().getName();

                if (clName.contains("InMemoryClassLoader")
                        || clName.contains("LspModuleClassLoader")
                        || clName.contains("XposedBridge")
                        || clName.contains("EdXposed")) {
                    findings.add("Suspicious ClassLoader: " + clName);
                }

                try {
                    cl.loadClass("org.lsposed.lspd.core.Main");
                    findings.add("LSPosed core class loadable via: " + clName);
                } catch (ClassNotFoundException ignored) {
                    // 正常
                }

                ClassLoader parent = cl.getParent();
                while (parent != null) {
                    String parentName = parent.getClass().getName();
                    if (parentName.contains("Xposed") || parentName.contains("Lsp")) {
                        findings.add("Suspicious parent ClassLoader: " + parentName);
                        break;
                    }
                    parent = parent.getParent();
                }
            }
        } catch (Throwable ignored) {
            // Hidden API 限制或异常，返回空列表避免误报
        }
        return findings;
    }

    /** 绕过 Hidden API 限制以访问 VMDebug.getInstancesOfClasses */
    private static void bypassHiddenApiRestrictions() {
        try {
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntimeClass.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Object runtime = getRuntime.invoke(null);
            Method setHiddenApiExemptions = vmRuntimeClass.getDeclaredMethod(
                    "setHiddenApiExemptions", String[].class);
            setHiddenApiExemptions.setAccessible(true);
            setHiddenApiExemptions.invoke(runtime, new Object[]{new String[]{"L"}});
        } catch (Throwable ignored) {
            // 部分设备可能失败
        }
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

    /**
     * 多方式读取 /proc 等路径：先 FileReader，失败则 exec("cat path")，提高兼容性、防止单一 API 在部分系统不可用。
     */
    private static String readProcFileWithFallback(String path) {
        try {
            return readFileContent(path);
        } catch (Throwable ignored) {
            // 部分系统/权限下 FileReader 不可用，用 exec 作为备用通道
        }
        java.lang.Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"/system/bin/cat", path});
            try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                process.waitFor();
                return sb.toString();
            }
        } catch (Throwable e) {
            throw new RuntimeException("Could not read " + path + " (FileReader and exec fallback failed)", e);
        } finally {
            if (process != null) process.destroy();
        }
    }
}

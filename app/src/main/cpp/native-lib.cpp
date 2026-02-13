#include <jni.h>
#include <string>
#include <android/log.h>

#include "detector/thread_detector.h"
#include "detector/memory_scanner.h"
#include "detector/port_scanner.h"
#include "detector/hook_detector.h"
#include "detector/so_integrity.h"
#include "detector/art_method_detector.h"
#include "detector/trap_detector.h"
#include "detector/xposed_detector.h"
#include "detector/anti_debug.h"

#define MAX_MEMORY_DETAILS 16

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

// Xposed path/fd detection: String[] { status, summary, detail0, ... }; uses syscall for paths
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectXposedPaths(JNIEnv *env, jclass clazz) {
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_xposed_path_and_fd_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;  /* 2 = DANGER, 0 = NORMAL */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Xposed-related paths or fd detected" : "No Xposed paths/fd detected"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("No Xposed path or linjector fd found"));
    } else {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    }
    return arr;
}

// SO Code Integrity：CRC(主) + GOT + 端口 + 匿名段 + 关键函数头部
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetSoIntegrityResult(JNIEnv *env, jclass clazz) {
    LOGD("[SO] check start");
    int r1 = check_libc_text_integrity();   /* 方案1: CRC 检测（主） */
    int r2 = detect_frida_got_hook();       /* 方案2: GOT 表 */
    int r3 = check_frida_port();            /* 方案3: 端口预检 */
    int r4 = scan_suspicious_anonymous_rx_memory();  /* 方案4: 匿名段 */
    int r0 = check_critical_functions();    /* 辅助: 关键函数头部 */
    int status = (r1 == 1 || r2 == 1 || r3 == 1 || r4 == 1 || r0 == 1) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    int any_skipped = (r1 == -1 && r2 == -1);
    const char *sum = (status == 2)
            ? "Frida detected (CRC/GOT/port anomaly)"
            : (any_skipped && r3 != 1 && r4 != 1) ? "Check skipped (libc not in process)"
            : "System library integrity OK";
    const char *det = (status == 2)
            ? "libc.so modified, GOT hijacked, or Frida server detected"
            : (any_skipped && r3 != 1 && r4 != 1) ? "Check skipped"
            : "No Frida detected";
    LOGD("[SO] check end: crc=%d got=%d port=%d mem=%d critical=%d status=%d", r1, r2, r3, r4, r0, status);
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(sum));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    return arr;
}

// ArtMethod 入口检测：Java 传入 jclass，Native 取关键方法 entry_point 是否在 libart/oat 外。返回值 -1 => Check skipped
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetArtMethodCheckResult(JNIEnv *env, jclass clazz, jclass targetClass) {
    char detailBuf[256];
    int r = art_method_check_entry_points(env, targetClass, detailBuf, sizeof(detailBuf));
    int status = (r == 1) ? 2 : 0;  /* 1=DANGER, 0=NORMAL, -1=skipped => NORMAL */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (r == 1) ? "Java method entry point outside libart/oat (possible Frida)"
            : (r == -1) ? "Could not perform check (maps or Activity not available)"
            : "ArtMethod entry points in expected range";
    const char *det = (r == -1 && detailBuf[0]) ? detailBuf : (r == -1) ? "Check skipped" : detailBuf;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    return arr;
}

// Hook 陷阱检测（SIGTRAP）：若本进程信号未被我们自己的 handler 捕获则疑为被劫持。返回值 -1 => Check skipped
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetTrapCheckResult(JNIEnv *env, jclass clazz) {
    int r = detect_trap_signal_handled();
    int status = (r == 1) ? 2 : 0;  /* 1=DANGER, 0=NORMAL, -1=skipped => NORMAL */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (r == 1) ? "SIGTRAP likely handled by external (e.g. Frida)"
            : (r == -1) ? "Could not perform check (signal or thread setup failed)"
            : "Signal trap check passed";
    const char *det = (r == 1) ? "Our SIGTRAP handler was not invoked"
            : (r == -1) ? "Check skipped" : "Our handler invoked as expected";
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    return arr;
}

// Hook detection for Java: String[] { status, summary, detail }; enhances Xposed detection
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectHook(JNIEnv *env, jclass clazz) {
    bool hooked = detect_hooks();
    int status = hooked ? 2 : 0;  /* 2 = DANGER, 0 = NORMAL */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(hooked ? "Hook/inline/PLT tampering detected" : "No hook detected"));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(hooked ? "Critical functions appear hooked or tampered" : "PLT/GOT and libc integrity OK"));
    return arr;
}

// Memory signature result for Java: String[] { status, summary, detail0, ... } (uses syscall)
// advancedChecks=true: anon exec memory threshold 4KB (vs 128KB default). n<0 => Check skipped.
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetMemorySignatureResult(JNIEnv *env, jclass clazz, jboolean advancedChecks) {
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_memory_signature_details_ex(details, MAX_MEMORY_DETAILS, advancedChecks ? 1 : 0);
    int status = (n > 0) ? 2 : 0;  // 2 = DANGER, 0 = NORMAL (含 n<0 无法检查)
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (n > 0) ? "Frida/LSPosed signatures in memory"
            : (n < 0) ? "Could not perform check (/proc/self/maps unreadable)"
            : "No Frida/LSPosed signatures in memory";
    const char *det = (n > 0) ? details[0] : (n < 0) ? "Check skipped" : "Memory scan completed - clean";
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    } else {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    }
    return arr;
}

// Frida thread detection for Java: String[] { status, summary, detail0, ... }; uses syscall. n<0 => Check skipped.
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectFridaThreads(JNIEnv *env, jclass clazz) {
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_frida_thread_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;  /* 2 = DANGER, 0 = NORMAL (含 n<0 无法检查) */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (n > 0) ? "Suspicious Frida-related thread(s) detected"
            : (n < 0) ? "Could not perform check (/proc/self/task unreadable)"
            : "No suspicious threads found";
    const char *det = (n > 0) ? nullptr : (n < 0) ? "Check skipped" : "No Frida-related thread names in /proc/self/task";
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    } else {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    }
    return arr;
}

// Port scan result for Java: String[] { status, summary, detail0, detail1, ... }
// Includes Frida ports + frida-server process + Frida processes (re.frida.helper etc.)
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetFridaPortScanResult(JNIEnv *env, jclass clazz) {
    detect_frida_ports();
    int portCount = get_frida_port_open_count();
    int processCount = get_frida_process_detail_count();
    int dbusCount = get_frida_dbus_detail_count();
    int n = portCount + processCount + dbusCount;
    int status = (n > 0) ? 2 : 0;  // 2 = DANGER, 0 = NORMAL
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);  // status, summary, then n details or 1 "All closed"
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Frida/IDA port(s) or Frida process(es) or D-Bus detected" : "No Frida/IDA ports or Frida processes detected"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("All Frida/IDA default ports closed, no Frida processes"));
    } else {
        int idx = 0;
        for (int i = 0; i < portCount; i++) {
            int port = get_frida_port_open_at(i);
            const char *detail;
            char buf[80];
            if (port == 0) {
                detail = "frida-server process with listening TCP (Frida 16+ random port)";
            } else if (port == 23946) {
                detail = "Port 23946 is open (IDA android_server)";
            } else {
                snprintf(buf, sizeof(buf), "Port %d is open (Frida default)", port);
                detail = buf;
            }
            env->SetObjectArrayElement(arr, 2 + idx++, env->NewStringUTF(detail));
        }
        for (int i = 0; i < processCount; i++) {
            const char *detail = get_frida_process_detail_at(i);
            if (detail) env->SetObjectArrayElement(arr, 2 + idx++, env->NewStringUTF(detail));
        }
        for (int i = 0; i < dbusCount; i++) {
            const char *detail = get_frida_dbus_detail_at(i);
            if (detail) env->SetObjectArrayElement(arr, 2 + idx++, env->NewStringUTF(detail));
        }
    }
    return arr;
}

// Thread detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaThread(JNIEnv *env, jobject thiz) {
    LOGD("Starting Frida thread detection...");
    return detect_frida_threads() ? JNI_TRUE : JNI_FALSE;
}

// Port detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaPort(JNIEnv *env, jobject thiz) {
    LOGD("Starting Frida port detection...");
    return detect_frida_ports() ? JNI_TRUE : JNI_FALSE;
}

// Memory signature detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaMemory(JNIEnv *env, jobject thiz) {
    LOGD("Starting Frida memory signature detection...");
    return detect_frida_memory_signatures() ? JNI_TRUE : JNI_FALSE;
}

// Debug mode detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectDebugMode(JNIEnv *env, jobject thiz) {
    LOGD("Starting debug mode detection...");
    return detect_debug_mode() ? JNI_TRUE : JNI_FALSE;
}

// Hook detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectHook(JNIEnv *env, jobject thiz) {
    LOGD("Starting hook detection...");
    return detect_hooks() ? JNI_TRUE : JNI_FALSE;
}

// Get detailed detection info
JNIEXPORT jstring JNICALL
Java_anti_rusda_MainActivity_nativeGetDetectionDetails(JNIEnv *env, jobject thiz) {
    std::string details = "Detection Details:\n\n";

    details += "Thread Detection: ";
    details += detect_frida_threads() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Port Detection: ";
    details += detect_frida_ports() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Memory Signature: ";
    details += detect_frida_memory_signatures() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Debug Mode: ";
    details += detect_debug_mode() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Hook Detection: ";
    details += detect_hooks() ? "SUSPICIOUS\n" : "CLEAN\n";

    return env->NewStringUTF(details.c_str());
}

} // extern "C"

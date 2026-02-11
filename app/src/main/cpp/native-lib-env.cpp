#include <jni.h>
#include <string>

/**
 * 环境检测 Native 库桩：供 EnvDetectionManager 加载 libenvdetect.so。
 * 当前环境检测主要在 Java 层实现；此处保留 JNI 接口便于后续将 Bootloader 等迁入 Native。
 */
extern "C" {

JNIEXPORT jstring JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeGetEnvVersion(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("1.0");
}

} // extern "C"

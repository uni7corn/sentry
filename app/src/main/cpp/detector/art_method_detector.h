#ifndef ART_METHOD_DETECTOR_H
#define ART_METHOD_DETECTOR_H

#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 检查传入的 jclass 中关键方法（如 onCreate）的 ArtMethod 入口是否在 libart/oat 范围内。
 * 若 entry_point 落在匿名可执行区或已知范围外，则疑为 Frida trampoline。
 * @param env JNIEnv
 * @param targetClass 目标类（如 android.app.Activity）
 * @param detailBuf 输出详情
 * @param detailSize detailBuf 大小
 * @return 0=未发现异常，1=疑似被 Hook，-1=无法检查（权限/解析失败，显示 Check skipped）
 */
int art_method_check_entry_points(JNIEnv *env, jclass targetClass, char *detailBuf, size_t detailSize);

#ifdef __cplusplus
}
#endif

#endif // ART_METHOD_DETECTOR_H

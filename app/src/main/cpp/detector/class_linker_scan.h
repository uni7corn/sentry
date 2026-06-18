#ifndef CLASS_LINKER_SCAN_H
#define CLASS_LINKER_SCAN_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 通过 JavaVM → Runtime → ClassLinker → class_loaders_ 链表暴力扫，返回链表节点数。
 *
 * out_cl_off / out_list_off：本次/缓存使用的偏移（用于诊断详情）；
 * 返回值：
 *   ≥0  链表节点计数（即当前进程中存活的 ClassLoader 数量）
 *   -1  扫描失败 / 偏移漂移 / libart 不可读 / Runtime 不可达
 */
int detect_classloader_count(JNIEnv *env, int *out_cl_off, int *out_list_off);

#ifdef __cplusplus
}
#endif

#endif // CLASS_LINKER_SCAN_H

# Sentry 检测规范文档

本文档详细描述 Sentry 安全检测应用中的各项检测、评分机制、实现方式以及设计目的。

> **维护要求**：本规范应与代码实现保持同步。根据 `.cursor/rules/modify-after-structure.mdc`，重大变更（如新增/删除检测项、修改实现层或逻辑等）完成后，须同步更新本文档及 `.cursor/skills/sentry-project-structure/SKILL.md`。

---

## 一、检测总览

Sentry 提供 **18 项** 安全检测，分为两类：

| 类别       | 数量 | 管理类                     | 展示位置   |
|------------|------|----------------------------|------------|
| 调试检测   | 7    | `DebugDetectionManager`    | 调试检测 Tab |
| 环境检测   | 11   | `EnvDetectionManager`     | 环境检测 Tab |

---

## 二、调试检测（7 项）

### 2.1 Frida Threads

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida 运行时创建的典型 GLib/线程名，用于发现 Frida 注入 |
| **实现层** | Native（C++，`thread_detector.cpp`） |
| **实现** | 使用 syscall（`my_open`/`my_read`/`my_close`）读取 `/proc/self/task/*/comm`，`my_strcasestr` 匹配关键词：`gmain`、`gdbus`、`pool-spawner`、`frida-agent`、`frida-gadget`、`frida`、`gum-js-loop`、`gthread`、`gpool` |
| **状态** | 检测到任意匹配 → `DANGER`；未检测 → `NORMAL` |

### 2.2 Frida Ports

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida 默认监听端口，防止 Frida Server 远程附加 |
| **实现层** | Native（C++，`port_scanner.cpp`） |
| **实现** | 1) 使用 **syscall**（`my_socket`/`my_connect`）连接本地 `127.0.0.1` 端口 27042、27043、27044、5000、8080；2) 读取 `/proc/self/net/tcp` 搜索十六进制端口码 `699A`(27042)、`699B`(27043)、`699C`(27044) |
| **状态** | 任意端口可连接或 net/tcp 发现端口模式 → `DANGER`；否则 `NORMAL` |
| **设计说明** | 使用 syscall 绕过 libc，降低 Frida/Xposed 对 `connect` 的 hook 影响 |

### 2.3 Memory Signatures

| 属性     | 说明 |
|----------|------|
| **目的** | 检测进程内存映射中是否存在 Frida/LSPosed 相关库或字符串 |
| **实现层** | Native（C++，`memory_scanner.cpp`） |
| **实现** | 使用 syscall `my_open`/`my_read` 读取 `/proc/self/maps`，逐行匹配签名：`frida`、`FRIDA`、`gum-js`、`gobject`、`gmain`、`frida-agent`、`frida-gadget`、`frida-server`、`liblspd.so`、`libriru.so` 等 |
| **状态** | 发现任一签名 → `DANGER`；未发现 → `NORMAL` |
| **设计说明** | 通过 syscall 与自实现字符串函数（如 `my_strcasestr`）减少 inline hook 风险 |

### 2.4 Named Pipes

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida 使用的 Unix 域套接字/管道名 |
| **实现层** | Java |
| **实现** | 读取 `/proc/self/net/unix`，搜索包含 `frida`、`gmain`、`gdbus` 的行 |
| **状态** | 发现 → `DANGER`；未发现 → `NORMAL` |

### 2.5 Ptrace / IDA Attach

| 属性     | 说明 |
|----------|------|
| **目的** | 检测当前进程是否被 ptrace 附加（如 IDA、gdb 附加调试） |
| **实现层** | Java |
| **实现** | 读取 `/proc/self/status`，解析 `TracerPid:` 字段；非 0 表示被附加 |
| **状态** | `TracerPid != 0` → `DANGER`；否则 `NORMAL` |

### 2.6 Debugger Attached

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Android 调试器是否已连接 |
| **实现层** | Java |
| **实现** | 调用 `Debug.isDebuggerConnected()` |
| **状态** | 已连接 → `DANGER`；否则 `NORMAL` |

### 2.7 Xposed / Hook Framework

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Xposed 框架及内联/PLT Hook |
| **实现层** | Java + Native（`hook_detector.cpp`） |
| **实现** | 1) Java：`Class.forName("de.robv.android.xposed.XposedBridge")`；2) Native：内联 Hook 检测（ARM64 指令分析）、PLT/GOT 完整性、libc 关键函数验证 |
| **状态** | 任意一项命中 → `DANGER`；否则 `NORMAL` |

---

## 三、环境检测（11 项）

### 3.1 Bootloader

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Bootloader 锁定状态与启动验证配置 |
| **实现层** | Native（`env_detector.cpp`） |
| **实现** | 读取 `ro.boot.verifiedbootstate`、`ro.boot.flash.locked`、`ro.boot.veritymode` 等系统属性；`orange`、`flash.locked=0`、`veritymode=disabled` 判为解锁 |
| **状态** | `verifiedbootstate=orange` / `flash.locked=0` / `veritymode=disabled` → `DANGER`；`warranty_bit=1` 或 AVB 版本缺失 → `WARNING`；否则 `NORMAL` |

### 3.2 Boot Image Integrity（引导镜像完整性）

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Magisk 等对 boot.img 的篡改，以及 dm-verity 状态 |
| **实现层** | Native（`env_detector.cpp`） |
| **实现** | 解析 `/proc/cmdline` 中 `androidboot.verifiedbootstate`、`androidboot.veritymode`；green=正常，yellow=自签名，orange=Magisk 篡改，red=AVB 失败；`veritymode=disabled/eio` 升级为 DANGER |
| **状态** | green → `NORMAL`；yellow → `WARNING`；orange/red 或 verity 禁用 → `DANGER`；eng/userdebug 构建会降级 DANGER→WARNING，减少误报 |
| **误报控制** | 部分设备无法读取 `/proc/cmdline`（厂商限制）或无 AVB 状态（如部分国产 ROM），视为 `NORMAL` 通过 |
| **权重** | `maxScore = 15`（显式设定为核心项） |

### 3.3 Magisk / Root

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Magisk 或其他 Root 环境 |
| **实现层** | Native + Java |
| **实现** | 1) Native：检测 `/data/adb/magisk`、`/data/adb/modules`、Shamiko（zygisk_shamiko）、zygisk_* 模块；2) Java：检查是否安装 `com.topjohnwu.magisk`、`io.github.huskydg.magisk` |
| **状态** | 任意一项存在 → `DANGER` |

### 3.4 LSPosed / Hook

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 LSPosed 及隐藏应用列表类工具 |
| **实现层** | Native + Java |
| **实现** | 1) Native：检测 `/data/adb/lspd`、`/data/adb/modules/zygisk_lsposed`；2) Java：检查是否安装 `dev.rikka.hide.myapplist`（Hide My Applist） |
| **状态** | 任意一项存在 → `DANGER` |

### 3.5 Play Integrity

| 属性     | 说明 |
|----------|------|
| **目的** | 通过 Google Play Integrity API 验证设备完整性 |
| **实现层** | Java（`PlayIntegrityHelper`） |
| **实现** | 请求 Integrity Token，可选服务端 `PlayIntegrityVerifier` 验证 |
| **状态** | 服务端验证通过 → `NORMAL`；仅取得 token 未配置验证 → `WARNING`；失败/超时 → `WARNING` 或 `DANGER` |
| **误报控制** | 无 Play Store / Play Services 的设备（华为等国产厂商）视为 `NORMAL` 通过，避免误报 |

### 3.6 Suspicious Files

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida Server、Magisk/LSPosed 相关可疑路径 |
| **实现层** | Native（`env_detector.cpp`） |
| **实现** | 1) 扫描 `/data/local/tmp` 中包含 `frida-server` 的文件；2) 检测 `/data/local/tmp/re.frida.server`；3) 检测 `/data/adb/magisk`、`/data/adb/modules`、`/data/adb/lspd` 等 |
| **状态** | 发现任意可疑路径 → `DANGER` |

### 3.7 Emulator

| 属性     | 说明 |
|----------|------|
| **目的** | 检测是否运行在模拟器环境 |
| **实现层** | Native（`env_detector.cpp`） |
| **实现** | 1) Build 属性匹配：`HARDWARE`/`PRODUCT`/`DEVICE`/`BRAND` 含 `generic`、`unknown`、`google_sdk`、`sdk`、`vbox86p`、`emulator`、`ranchu`、`goldfish` 等；2) 检测 `/dev/socket/qemud`、`/dev/qemu_pipe`、`/system/lib/libc_malloc_debug_qemu.so` 等；3) BlueStacks 配置 `/data/misc/emu/update_check.cfg` |
| **状态** | 发现指标 → `WARNING`（避免对部分真机误报） |

### 3.8 Kernel Patch

| 属性     | 说明 |
|----------|------|
| **目的** | 检测内核安全补丁是否过于陈旧 |
| **实现层** | Java |
| **实现** | 解析 `Build.VERSION.SECURITY_PATCH` 日期，计算距今月数；≥24 月 → `DANGER`；≥12 月 → `WARNING` |
| **状态** | 根据补丁年龄分级 |

### 3.9 ADB Debug

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 USB/WiFi ADB 是否开启，以及 5555 端口是否开放 |
| **实现层** | Java + Native |
| **实现** | 1) Java：`Settings.Global.adb_enabled`、`adb_wifi_enabled`；2) Native：syscall 检查 `127.0.0.1:5555` 是否可连接 |
| **状态** | 任意一项开启 → `WARNING`（仅提示不扣分：`warnOnly=true`，部分设备需开启 ADB 做开发） |

### 3.10 Multi-instance（多开）

| 属性     | 说明 |
|----------|------|
| **目的** | 检测应用是否运行于多开/分身环境 |
| **实现层** | Java |
| **实现** | 包名包含 `:` 或 `dual`；`getFilesDir()` 路径含 `parallel`、`dual`、`clone`、`multi` |
| **状态** | 符合 → `WARNING` |

### 3.11 Container / Virtualization

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 VirtualApp、Parallel Space 等容器/虚拟化环境 |
| **实现层** | Java + Native |
| **实现** | 1) Java：包名 vs `/proc/self/cmdline` 进程名不一致；2) Java：检查 `io.va.exposed`、`com.lody.virtual`、`me.weishu.exp`、`com.parallel.space.lite`、`com.excelliance.dualaid` 是否安装；3) Native：读取 `/proc/1/cgroup` 检测 `lxc`、`docker`、`kubepods` |
| **状态** | 任意一项命中 → `DANGER` |

---

## 四、评分机制

### 4.1 状态与得分

每项检测有三种状态：

| 状态常量 | 数值 | 含义   |  earnedScore |
|----------|------|--------|--------------|
| `STATUS_NORMAL`  | 0 | 正常/安全 | `maxScore`（满分） |
| `STATUS_WARNING` | 1 | 警告     | `maxScore / 2`（若 `warnOnly=true` 则为满分，只提示不扣分） |
| `STATUS_DANGER`  | 2 | 危险     | `0` |

### 4.2 满分与权重

- 默认 `DEFAULT_MAX_SCORE = 10`
- **核心项加权**：Play Integrity **15**、Boot Image Integrity **15**、Magisk/Root **12**
- **辅助项降权**：ADB Debug **5**、Multi-instance **5**、Container **8**
- 其他项采用默认 10 分

### 4.3 总分计算

```
总分 = Σ earnedScore
满分 = Σ maxScore
安全百分比 = (总分 / 满分) × 100%
```

- 调试检测 7 项 + 环境检测 11 项，共 18 项
- 总分在概览页以百分比形式展示

### 4.4 Native 返回格式

Native 检测统一返回 `String[]`：
- `[0]`：状态数字字符串（`"0"` / `"1"` / `"2"`）
- `[1]`：摘要 summary
- `[2..n]`：详情 details

---

## 五、设计与实现原则

### 5.1 Native 优先

- 文件、端口、内存、进程等敏感检测优先放在 **Native 层**
- 降低被逆向、篡改和 hook 的风险
- 调试检测：`DebugDetectionManager` + `native-lib.cpp` + `port_scanner` / `memory_scanner`
- 环境检测：`EnvDetectionManager` + `native-lib-env.cpp` + `env_detector.cpp`

### 5.2 Syscall 优先

- 敏感 I/O、网络、文件访问优先使用 **syscall**，绕过 libc
- 使用 `syscall_utils.cpp` 提供的：`my_open`、`my_read`、`my_close`、`my_access`、`my_socket`、`my_connect`、`my_strstr`、`my_strcmp` 等
- 减少 Frida/Xposed 对 libc 的 hook 影响

### 5.3 误报控制

- 单指标不足以断定异常时，结合多项证据（如模拟器需硬件属性 + 文件 + 端口）
- 不确定时使用 `STATUS_WARNING` 而非 `STATUS_DANGER`
- 特定环境做降级：如 eng/userdebug 的 Boot Image Integrity 将 DANGER 降为 WARNING

### 5.4 核心 vs 辅助

- 核心安全项（Frida、Root、ptrace、Boot Image 等）可提高 maxScore
- 辅助项（多开、ADB 等）可降低 maxScore，避免过度影响总分

---

## 六、检测流程图

```
App 启动
    ↓
DetectionManager 初始化
    ↓
并行执行 {
    DebugDetectionManager.runAllDetections()   ← 7 项
    EnvDetectionManager.runAllDetections()     ← 11 项
}
    ↓
收集 DetectionResult 列表
    ↓
总分 = Σ(earnedScore) / Σ(maxScore)
    ↓
UI 展示（OverviewFragment）
    - 总分百分比
    - 分类详情（调试检测 Tab / 环境检测 Tab）
```

---

## 七、绕过难度评估

| 检测项 | 绕过难度 | 原因 |
|--------|---------|------|
| Play Integrity | ⭐⭐⭐⭐⭐ | 硬件 TEE 验证，服务端决策 |
| Boot Image Integrity | ⭐⭐⭐⭐⭐ | Bootloader 验证，内核 cmdline |
| Frida Ports (Native) | ⭐⭐⭐⭐ | Syscall 实现，难 Hook |
| Memory Signatures | ⭐⭐⭐⭐ | Syscall + 自实现字符串函数 |
| Frida Threads (Native) | ⭐⭐⭐⭐ | Syscall，难 Hook |
| Magisk/Root (Native) | ⭐⭐⭐⭐ | Syscall 文件检测 |
| Xposed (Java+Native) | ⭐⭐⭐ | 反射 + Native 双检测 |
| Container (Native cgroup) | ⭐⭐⭐ | 需伪造 cgroup 环境 |
| Debugger Attached | ⭐⭐ | 单 API 调用，易被 Hook |
| Ptrace | ⭐⭐ | 读取 /proc，可被 Hook |

---

## 八、检测目的汇总

| 目的             | 对应检测项 |
|------------------|------------|
| 防 Frida 注入    | Frida Threads、Frida Ports、Memory Signatures、Named Pipes、Suspicious Files |
| 防调试器附加     | Ptrace、Debugger Attached |
| 防 Root/Hook     | Magisk/Root、LSPosed/Hook、Xposed、Boot Image Integrity |
| 设备完整性       | Play Integrity、Bootloader、Kernel Patch |
| 防模拟器/容器    | Emulator、Container/Virtualization |
| 开发/运维风险    | ADB Debug、Multi-instance |

---

## 九、相关文件速查

| 用途         | 路径 |
|--------------|------|
| 调试检测入口 | `app/src/main/java/anti/rusda/detector/DebugDetectionManager.java` |
| 环境检测入口 | `app/src/main/java/anti/rusda/detector/EnvDetectionManager.java` |
| 结果模型     | `app/src/main/java/anti/rusda/detector/DetectionResult.java` |
| 端口扫描     | `app/src/main/cpp/detector/port_scanner.cpp` |
| 线程检测     | `app/src/main/cpp/detector/thread_detector.cpp` |
| 内存扫描     | `app/src/main/cpp/detector/memory_scanner.cpp` |
| Hook 检测    | `app/src/main/cpp/detector/hook_detector.cpp` |
| 环境检测 C++ | `app/src/main/cpp/detector/env_detector.cpp` |
| Syscall 工具 | `app/src/main/cpp/utils/syscall_utils.cpp` |
| 开发规范     | `.cursor/rules/detection-development.mdc` |

# Sentry 检测规格 · Detection Specification

> 本文档与代码同步，描述每项检测的原理、命中条件、状态映射、权重与已知限制。所有路径都指向 `app/src/main/`。

## 目录

- [设计原则](#设计原则)
- [总体评分](#总体评分)
- [Debug Tab · 11 项](#debug-tab--11-项)
  - [D1. Frida Threads](#d1-frida-threads)
  - [D2. Frida Ports](#d2-frida-ports)
  - [D3. Memory Signatures](#d3-memory-signatures)
  - [D4. Maps detection (Java exec)](#d4-maps-detection-java-exec)
  - [D5. Ptrace / IDA Attach](#d5-ptrace--ida-attach)
  - [D6. Debugger Attached](#d6-debugger-attached)
  - [D7. Xposed / Hook Framework](#d7-xposed--hook-framework)
  - [D8. SO Code Integrity](#d8-so-code-integrity)
  - [D9. ArtMethod Entry](#d9-artmethod-entry)
  - [D10. Hook Trap](#d10-hook-trap)
  - [D11. Dirty Page / Memory Injection](#d11-dirty-page--memory-injection)
- [Environment Tab · 10 项](#environment-tab--10-项)
  - [E1. App Signature](#e1-app-signature)
  - [E2. Bootloader](#e2-bootloader)
  - [E3. Magisk / Root](#e3-magisk--root)
  - [E4. Dangerous Apps（warnOnly）](#e4-dangerous-appswarnonly)
  - [E5. Suspicious Files](#e5-suspicious-files)
  - [E6. Emulator](#e6-emulator)
  - [E7. Kernel Patch（warnOnly）](#e7-kernel-patchwarnonly)
  - [E8. ADB Debug（warnOnly）](#e8-adb-debugwarnonly)
  - [E9. Multi-instance](#e9-multi-instance)
  - [E10. Container / Virtualization](#e10-container--virtualization)
- [平台覆盖与已知限制](#平台覆盖与已知限制)

---

## 设计原则

1. **可解释优先**：每项检测必须能给出"为什么"的具体证据（哪个线程、哪个映射、哪条 prop），结果区分 `NORMAL / WARNING / DANGER` 三态。
2. **多通道交叉验证**：同一目标至少两条独立路径（如 maps 走 Native syscall + Java exec `cat`），降低单点 Hook 致盲。
3. **syscall 优先**：sensitive I/O 直走 `svc` 指令，规避 libc 全局 Hook。失败再回退 libc，兼顾兼容性。
4. **误报零容忍**：对正常用户（合法 GLib、未越狱 Pixel、开发者模式日常使用）应给出 `NORMAL`。任何已知会在干净设备触发 DANGER 的启发都必须降级或修复。
5. **warnOnly 解耦运营**：开 ADB、补丁陈旧、装了 Xposed 模块——这些"运维事实"仅警示不扣分。

## 总体评分

```
score = Σ(debug_item.earned × 1.5) + Σ(env_item.earned)
max   = Σ(debug_item.max    × 1.5) + Σ(env_item.max)
percent = round(100 × score / max)
```

- 单项满分：默认 10；`Bootloader`/`App Signature` 15、`Magisk/Root` 12、`Kernel Patch` 10、`Container` 8、`Dangerous Apps`/`ADB Debug`/`Multi-instance`/`Suspicious Files`/`Emulator` 5。
- `STATUS_NORMAL → maxScore`；`STATUS_WARNING → maxScore/2`（`warnOnly` 时仍取 maxScore）；`STATUS_DANGER → 0`。
- 调试域 1.5× 权重在 [`MainActivity.applyDebugScoreWeight`](../app/src/main/java/anti/rusda/MainActivity.java)；调整权重时务必同步更新本文。

按当前权重的实际理论满分：

| 维度 | 项目数 | 单项 maxScore 累计 | × 权重 | 域满分 |
|---|---|---|---|---|
| Debug | 11 | 11 × 10 = 110 | × 1.5 | **165** |
| Environment | 10 | 15+15+12+5+5+5+10+5+5+8 = 85 | × 1 | **95** |
| **总计** | 21 | — | — | **260** |

> 即首页"100"代表 `score/260 = 100%`，并非 README 历史描述的 205。

---

## Debug Tab · 11 项

### D1. Frida Threads

| 字段 | 值 |
|---|---|
| 实现 | [`thread_detector.cpp:get_frida_thread_details()`](../app/src/main/cpp/detector/thread_detector.cpp) |
| 触发条件 | `/proc/self/task/*/comm` 内容命中 Frida 专属关键词 |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | hit → DANGER，目录读不到 → Check skipped |

**关键词（白名单严格收紧）**：`gum-js-loop` / `frida-agent` / `frida-gadget` / `frida-server` / `frida-helper` / `linjector`。

历史版本曾包含 `gmain`/`gdbus`/`gthread`/`gpool`/`gjs-context`，但这些是 GLib 标准线程名，**正常使用 GLib 的合法库会触发误报**——已在本版本移除。Frida 在被注入进程里仍会启动 GLib 线程，但需配合 [D3](#d3-memory-signatures) maps 上的 Frida ELF 才能判断，单靠 `comm` 不可靠。

**已知限制**：Linux `comm` 字段截短到 15 字节，`frida-server` 截短后仍为 `frida-server`，但更长的命名（如自定义 agent）会被截短为前 15 字节，特征关键词必须落在前 15 字节内。

### D2. Frida Ports

| 字段 | 值 |
|---|---|
| 实现 | [`port_scanner.cpp:detect_frida_ports()`](../app/src/main/cpp/detector/port_scanner.cpp) + [`native-lib.cpp` JNI 拼装](../app/src/main/cpp/native-lib.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | 任一通道命中 → DANGER |

**四条通道**：

1. **直连默认端口**：syscall `connect()` 探测 `27042 (Frida)` 与 `23946 (IDA android_server)`。
2. **`/proc/net/tcp` LISTEN(0A)**：逐行扫描，仅当行内含 `:699A `（27042）或 `:5D8A `（23946）且状态字段为 `0A` 才命中（边界匹配，避免远端地址误命）。
3. **frida-server 随机端口**：遍历 `/proc/<pid>/comm` 找包含 `frida-server` 的进程，读对应 `/proc/<pid>/net/tcp` 看是否有 LISTEN，覆盖 `frida-server -l 0.0.0.0:0` 随机端口场景。
4. **D-Bus AUTH 探测**：对 `/proc/net/tcp` 中所有 LISTEN 的本机端口（127.0.0.1 **或 INADDR_ANY 0.0.0.0**，本版本扩展）发短 `\x00 AUTH\r\n`，预期 frida-core 返回 `REJECT` 开头。

**进程名扫描**：同时记录 `re.frida.helper` / `re.frida.server` 等进程。

**已知误报**：D-Bus 探测对正在监听本机的 D-Bus 服务（部分开发工具）也可能返回 REJECT；可接受，因为 D-Bus 本身也属调试态。

### D3. Memory Signatures

| 字段 | 值 |
|---|---|
| 实现 | [`memory_scanner.cpp:get_memory_signature_details_ex()`](../app/src/main/cpp/detector/memory_scanner.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | 命中签名 / 可疑匿名 RX → DANGER |

**两条信号**：

1. **maps 签名扫描**：对 `/proc/self/maps` 的每一行做不区分大小写的子串匹配，列表包含 `frida` / `gum-js` / `gumjs` / `frida-agent` / `frida-gadget` / `frida-java-bridge` / `linjector` / `quickjs` / `libquickjs` / `liblspd.so` / `libriru*.so` / `libxposed*` / `XposedBridge` / `XposedHelpers` / `de.robv.android.xposed` / `org.lsposed` / `zygisk_lsposed` / `zygisk`。
2. **匿名 RX 段启发**：大小阈值默认 128 KB（设置中"高级检测"开启后降至 4 KB，灵敏度上但误报增）；且通过白名单排除 JIT/scudo/linker_alloc/dalvik-jit 等良性段。命中时进一步扫描 ARM64 `LDR X16/X17,[PC]; BR X16/X17` Trampoline 模式，**至少 2 处** 才作为强证据。

**为什么不用磁盘 CRC**：在 Android 10+ SELinux 与 XOM（Execute-Only Memory）下，直接读 `/system/`、`/apex/` 的 SO 容易 EACCES 或触发 SIGSEGV；本项放弃磁盘比对路径，专注内存证据。

### D4. Maps detection (Java exec)

| 字段 | 值 |
|---|---|
| 实现 | [`DebugDetectionManager.detectMapsViaExec()`](../app/src/main/java/anti/rusda/detector/DebugDetectionManager.java) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | maps 命中签名 → DANGER；读不到 → Check skipped |

与 D3 走的是 **不同代码路径**：D3 用 syscall，D4 用 `BufferedReader(new FileReader("/proc/<pid>/maps"))`，失败回退 `Runtime.exec("/system/bin/cat ...")`。签名列表与 D3 共用。

**意义**：D3 是 syscall，D4 是 Java；一旦 Frida 只 Hook 了其中一条路径（仅 patch libc 或仅 patch ART），另一条仍可看见。Sentry 把两个都作为独立打分项以鼓励"双通道"理念。

### D5. Ptrace / IDA Attach

| 字段 | 值 |
|---|---|
| 实现 | [`DebugDetectionManager.detectPtraceStatus()`](../app/src/main/java/anti/rusda/detector/DebugDetectionManager.java) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | `TracerPid != 0` → DANGER |

读 `/proc/self/status` 的 `TracerPid` 行；同样 FileReader → exec 双通道。`State: t/T` 也作为附加状态附在详情中（不单独判分）。

### D6. Debugger Attached

| 字段 | 值 |
|---|---|
| 实现 | [`DebugDetectionManager.detectDebuggerAttached()`](../app/src/main/java/anti/rusda/detector/DebugDetectionManager.java) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | `android.os.Debug.isDebuggerConnected() == true` → DANGER |

调用 Android SDK API。可被 Hook 但成本不低。开发者在 IDE 调试自己 App 时此项会 DANGER —— 这是正确行为而非误报。

### D7. Xposed / Hook Framework

| 字段 | 值 |
|---|---|
| 实现 | [`DebugDetectionManager.checkLibraryIntegrity()`](../app/src/main/java/anti/rusda/detector/DebugDetectionManager.java) + [`hook_detector.cpp`](../app/src/main/cpp/detector/hook_detector.cpp) + [`xposed_detector.cpp`](../app/src/main/cpp/detector/xposed_detector.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | 任一证据成立 → DANGER |

**Java 侧**：
1. `Class.forName("de.robv.android.xposed.XposedBridge")` —— 经典 Xposed。
2. 抛异常看堆栈是否含 XposedBridge / XposedHelpers / org.lsposed。
3. 反射检查 `findAndHookMethod` / `hookAllMethods` 方法存在性。
4. 通过 `dalvik.system.VMDebug.getInstancesOfClasses` 找 `InMemoryClassLoader` / `LspModuleClassLoader` —— **判断"本进程被 hook"**，而非"系统上装了 LSPosed Manager"。

**Native 侧**：
1. `xposed_detector` 扫 Xposed/LSPosed/Riru 已知 SO 路径、`ro.dalvik.vm.native.bridge` 可疑值、`LD_PRELOAD` / `MAGISKTMP`、`/proc/self/fd` 中的 `linjector`。
2. `hook_detector.check_inline_hooks` 读取 `dlsym(malloc/free/open/...)` 的前 8 字节，匹配 ARM64 `LDR+BR` 或长跳转模式。
3. `hook_detector.check_plt_hooks` —— GOT 指针逃逸：若 dlsym 结果落入"可疑匿名 RX"段，疑为 trampoline。
4. ARM64 LR 检测：从汇编取 `x30`，若返回地址不在自身模块范围内，疑为内联 hook trampoline。

**修复（本版本）**：
旧 `check_library_integrity` 硬编码 `/system/lib64/libc.so` / `/system/lib/libc.so`，但 Android 10+ libc 在 `/apex/com.android.runtime/lib64/bionic/libc.so`，且 SELinux 禁止 untrusted_app 读 `/system/lib64`。打不开就判 hooked → **几乎所有现代设备误报**。已改为通过 `dl_iterate_phdr` 取本进程实际加载的 libc 路径并降级该信号（不能仅凭 open 失败判 DANGER）。

### D8. SO Code Integrity

| 字段 | 值 |
|---|---|
| 实现 | [`so_integrity.cpp`](../app/src/main/cpp/detector/so_integrity.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | 任一子检测 == 1 → DANGER |

**五个子检测**（任一命中即 DANGER）：

1. **CRC**（`check_libc_text_integrity`）：通过 `dl_iterate_phdr` 拿到 libc 路径与第一个 PT_LOAD/PF_X 段的 offset/size，分块 CRC32 对比磁盘文件与内存的 `.text`。Android 10+ 下 `/apex/.../libc.so` 在多数设备可读，但 SELinux 严格的 OEM 可能拒绝；此时返回 -1（Check skipped）。
2. **GOT**（`detect_frida_got_hook`）：`dlsym(open/read/strcmp)` 的解析地址若不在 libc PT_LOAD 范围内 → 被 GOT 劫持。
3. **端口**（`check_frida_port`）：libc 级 connect(27042) 预检（与 D2 重复，作为快速路径）。
4. **匿名 RX**（`scan_suspicious_anonymous_rx_memory`）：与 D3 共享匿名段启发，但加上白名单（dalvik-jit/scudo/linker_alloc 等）和大小判断；小段直接扫 Frida 8 字节 trampoline 指纹，大段直接 DANGER。
5. **关键函数头**（`check_critical_functions`）：检查 `open/read/strcmp/strstr` 头 8 字节是否精确等于 Frida `LDR X16/X17, [PC, #8]; BR X16/X17` 特征码。

### D9. ArtMethod Entry

| 字段 | 值 |
|---|---|
| 实现 | [`art_method_detector.cpp:art_method_check_entry_points()`](../app/src/main/cpp/detector/art_method_detector.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | 任一有效 entry 落在所有合法 exec 区间外 → DANGER |

**原理**：JNI 取 `Activity.onCreate` 的 `jmethodID`（即 ART 的 `ArtMethod*`），读其 entry_point（偏移 48/56/64 视 ART 版本而定）。若该地址不在 `/proc/self/maps` 的任一可执行段内，说明被 Frida Java hook 重定向到了 libart/oat 外的代码岛。

**修复（本版本）**：旧实现用 256 KB 固定 buffer 一次性读 maps；现代 App 进程 maps 常 >1 MB，超出部分被截断 → 落在后段的合法 entry 被误判为 trampoline。已改为分块 IO + 流式行解析，仅以可执行段数 256 为上限兜底。

### D10. Hook Trap

| 字段 | 值 |
|---|---|
| 实现 | [`trap_detector.cpp:detect_trap_signal_handled()`](../app/src/main/cpp/detector/trap_detector.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | 自有 handler 未运行 → DANGER；setup 失败 → Check skipped |

在专用 pthread 内安装 `SIGTRAP` handler，用 `tgkill(self_pid, self_tid, SIGTRAP)` 仅向本线程发信号，handler 内 `siglongjmp` 跳回。若信号被外部 handler 吞掉（典型如 Frida 的 signal chaining），自家 handler 不会运行 → 疑似被劫持。专用线程避免 UI 线程跨线程 longjmp 崩溃。

### D11. Dirty Page / Memory Injection

| 字段 | 值 |
|---|---|
| 实现 | [`env_detector.cpp:env_detect_zygisk_injection()`](../app/src/main/cpp/detector/env_detector.cpp) |
| 权重 | maxScore = 10（× 1.5 = 15） |
| 状态 | smaps / VMap / pagemap 任一命中 → DANGER |

**三条信号**：

1. **smaps Private_Dirty**：扫 `/proc/self/smaps`，对 libart/libc/libselinux/libandroid_runtime 等关键库的可执行段查看 `Private_Dirty > 0`（正常代码段共享只读，不应有私有脏页）。白名单：`code_cache`、`libstagefright.so`（媒体解码常见少量脏页）。
2. **VMap 字符串**：扫 maps 中 anon r-x 段内存内容，搜 `zygisk_module_entry` / `libzygisk.so` / `ZygiskModule` / `zygisk` 字符串。
3. **Pagemap soft-dirty (bit 55)**：读 `/proc/self/pagemap`，对 libc `fork/vfork/signal` 函数所在页查看 bit 55（COW/已写痕迹）。

**已知限制（重要）**：
- pagemap 在大多数现代 Android 上对 `untrusted_app` **返回 PFN/flags 全 0**（kernel 安全策略，对非 root 进程不暴露物理页信息），此通道实际可能持续返回 0。代码已采用"present 且 soft_dirty"双条件以避免把"读不到"误判为"已 hook"，但实际命中率较低。
- smaps 的 `Private_Dirty` 也依赖 kernel 对 untrusted_app 的暴露策略，部分设备会全 0。

---

## Environment Tab · 10 项

### E1. App Signature

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectAppSignature()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) + [`signature_checker.cpp`](../app/src/main/cpp/detector/signature_checker.cpp) |
| maxScore | 15 |
| 状态 | 不匹配 → DANGER；预期值未注入（Debug 构建）→ Check skipped/NORMAL |

**机制**：构建时由 Gradle 读 `release.keystore` 的 SHA-256 注入到 native（`-DEXPECTED_SIGNATURE_SHA256=...`），运行时 Java 取当前 APK 签名 SHA-256 传给 native 比对。比对发生在 native，是为了让"先 Hook Java verifier"的简单绕过失效。

**早期 fail-fast**：[`SentryApp.onCreate()`](../app/src/main/java/anti/rusda/SentryApp.java) 在最早期调用 `verifyAppSignatureAtStartup`，不匹配则 `killProcess(myPid())` —— 缩小被二次打包后业务层的可达性。

### E2. Bootloader

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectBootloader()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) + [`env_detector.cpp:env_detect_bootloader()`](../app/src/main/cpp/detector/env_detector.cpp) + [`KeyAttestationHelper`](../app/src/main/java/anti/rusda/detector/KeyAttestationHelper.java) |
| maxScore | 15 |
| 状态 | unlocked / verity disabled / deviceLocked=false → DANGER；属性不全或 self-signed → WARNING |

**三层证据**：

1. **AVB 属性**：`ro.boot.verifiedbootstate` / `flash.locked` / `veritymode` / `vbmeta.device_state` / `warranty_bit` / `avb_version` / `sys.oem_unlock_allowed`。命中 `orange`/`unlocked`/`disabled`/`flash.locked=0` → DANGER。`yellow` / `avb_version=1.0` / `warranty_bit=1` / `OEM unlock allowed` → WARNING。
2. **OEM Unlock 交叉验证**：Native `sys.oem_unlock_allowed` vs Java `Settings.Global.oem_unlocking_enabled` —— 不一致疑似 prop hook。注意：这两个值在多数设备上对普通应用都是不可读/恒 0，所以"都为 0"不是异常。
3. **Key Attestation**：调用 Keystore TEE 生成密钥并取出证书链，解析 RootOfTrust 扩展拿 `deviceLocked` / `verifiedBootState` / `verifiedBootKey` / `verifiedBootHash`。这是硬件级证明，最难绕过。

**为什么不仅靠属性**：`__system_property_get` 可以被 Magisk resetprop 覆盖，纯属性不够。TEE 证书链由硬件根密钥签名，覆盖代价远高。

### E3. Magisk / Root

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectRoot()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) + [`env_detector.cpp:env_detect_magisk()`](../app/src/main/cpp/detector/env_detector.cpp) |
| maxScore | 12 |
| 状态 | 任何 Magisk 痕迹 → DANGER |

**信号**：
- `/data/adb/magisk` / `/data/adb/modules` 目录存在（syscall access）。
- `/data/adb/modules/zygisk_shamiko` —— Shamiko 隐藏模块。
- `/data/adb/modules/zygisk_*` —— Zygisk 模块。
- Java 包管理器枚举 `com.topjohnwu.magisk` / `io.github.huskydg.magisk`。

**已知限制**：通用 `su` 二进制检测已主动去掉（误报多、价值低）。

### E4. Dangerous Apps（warnOnly）

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectXposedModules()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) + [`env_detector.cpp:env_verify_xposed_modules()`](../app/src/main/cpp/detector/env_detector.cpp) |
| maxScore | 5 |
| 状态 | 命中 → WARNING（warnOnly 不扣分） |

**三路：**
1. `PackageManager.getInstalledPackages(GET_META_DATA)` —— 经典 metaData 路径，容易被 Hide My Applist 等隐藏。
2. `queryIntentActivities(ACTION_MAIN/CATEGORY_LAUNCHER)` —— 与方式1 交叉。
3. Native 读 APK ZIP 找 `assets/xposed_init`（syscall），以及 `modules.list`（需 root）。

**风控应用**（非 Xposed 但属"重型工具"）：`bin.mt.plus` / `com.mi.mi.mtmanager`（MT 管理器）、`com.termux`。

**为什么 warnOnly**：装了 LSPosed Manager 不等于本进程被 hook。系统上有此类工具应警示而非判死。

### E5. Suspicious Files

| 字段 | 值 |
|---|---|
| 实现 | [`env_detector.cpp:env_detect_suspicious_files()`](../app/src/main/cpp/detector/env_detector.cpp) |
| maxScore | 5 |
| 状态 | 命中 → DANGER |

扫 `/data/local/tmp/` 含 `frida-server` 的文件名、`/data/local/tmp/re.frida.server`，以及 `/data/adb/magisk` / `/data/adb/modules` / `/data/adb/lspd` 三个核心目录。`/system/xbin`、`/sdcard` 路径已移除（误报多、对现代 Android 失去意义）。

**已知限制**：app 进程对 `/data/adb/*` 通常无读权限（root-only 目录），`my_access(F_OK)` 在多数设备返回 EACCES → -1，相当于检测不到。这是为 root 设备保留的信号通道，对非 root 设备意义有限。

### E6. Emulator

| 字段 | 值 |
|---|---|
| 实现 | [`env_detector.cpp:env_detect_emulator_files()`](../app/src/main/cpp/detector/env_detector.cpp) |
| maxScore | 5 |
| 状态 | 命中 → WARNING |

**Build.* 指纹**：`generic`/`unknown`/`google_sdk`/`sdk`/`sdk_x86`/`vbox86p`/`emulator`/`simulator`/`ranchu`/`goldfish` —— 经典 QEMU/goldfish。
**本版本新增**：`cuttlefish` / `cf_x86_64` / `cf_arm64` / `vsoc`（Cuttlefish，AOSP 14+ 主流）；`redroid`（Linux 容器化 Android）；`nox` / `mumu` / `ldplayer` / `memu`（国内 PC 模拟器）。

**文件指纹**：`/dev/socket/qemud` / `/dev/qemu_pipe` / `/system/lib/libc_malloc_debug_qemu.so` / `/sys/qemu_trace` / `/system/bin/qemu-props` / `/dev/socket/cuttlefish`、BlueStacks 配置文件。

### E7. Kernel Patch（warnOnly）

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectKernelPatch()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) |
| maxScore | 10 |
| 状态 | 补丁 ≥ 12 月 → WARNING；≥ 24 月 → WARNING（标更陈旧） |

读 `Build.VERSION.SECURITY_PATCH` 解析年月日，与当前时间作差。**warnOnly：不扣分**，因为补丁陈旧≠灰产设备，老用户 OEM 不推更新很常见。

### E8. ADB Debug（warnOnly）

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectAdbEnhanced()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) + [`env_detector.cpp:env_detect_adb()`](../app/src/main/cpp/detector/env_detector.cpp) |
| maxScore | 5 |
| 状态 | 任一证据 → WARNING（warnOnly） |

**Native（syscall，抗 ContentResolver Hook）**：
1. syscall connect() 探 5555/5556/5557/5558。
2. **逐行解析 `/proc/net/tcp`**：要求同一行包含 `:15B3 ` 等边界端口 **且** ` 0A ` LISTEN 状态。本版本修复：旧实现裸搜 `15B3` 可能误命中远端地址。
3. 扫 `/proc/<pid>/comm` 找 `adbd`。
4. 读 `/sys/class/android_usb/android0/state` 看是否 `CONFIGURED/CONNECTED`。

**Java**：`Settings.Global.adb_enabled` / `adb_wifi_enabled`、`Settings.Secure.development_settings_enabled`。
**Exec 兜底**：`getprop init.svc.adbd`、`settings get global adb_enabled` 等命令行通道，绕过 ContentResolver Hook。

### E9. Multi-instance

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.checkProcessStatus()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) |
| maxScore | 5 |
| 状态 | 包名/dataDir 命中"dual/parallel/clone/multi" → WARNING |

### E10. Container / Virtualization

| 字段 | 值 |
|---|---|
| 实现 | [`EnvDetectionManager.detectContainer()`](../app/src/main/java/anti/rusda/detector/EnvDetectionManager.java) + [`env_detector.cpp:env_detect_cgroup()`](../app/src/main/cpp/detector/env_detector.cpp) |
| maxScore | 8 |
| 状态 | 任一证据 → DANGER |

**三条信号**：
1. **包名 vs cmdline**：`context.getPackageName()` 与 `/proc/self/cmdline` 不一致——VirtualApp 类容器的标志。
2. **已知容器包名**：`io.va.exposed` / `com.lody.virtual` / `me.weishu.exp`（太极）/ `com.parallel.space.lite` / `com.excelliance.dualaid`。
3. **`/proc/1/cgroup`**：含 `lxc` / `docker` / `kubepods`。

---

## 平台覆盖与已知限制

### 架构

仅构建 `arm64-v8a`（[`app/build.gradle`](../app/build.gradle) `abiFilters`）。Native 内含 ARMv7 syscall 代码路径，但 APK 不打 32 位 ABI，32 位机型会 `UnsatisfiedLinkError` 后 Java 兜底（多数检测会标 Check skipped）。

### Android 版本

- **minSdk 24**（Android 7）、**targetSdk 36**。
- **Android 10+** 的影响：
  - libc 迁至 `/apex/com.android.runtime/lib64/bionic/libc.so`，SELinux 限制部分 `/system/lib*` 访问 —— D7 的 `check_library_integrity` 已修复路径硬编码问题。
  - SELinux 普遍阻止 untrusted_app 读 `/proc/<other_pid>/*` —— 跨进程探测受限。
  - `/proc/self/pagemap` 对非 root 进程返回 0 化页表 —— D11 的 pagemap 通道大概率仅在 root 进程下有效。
- **Android 14+**：apex 域更严格，CRC（D8）走 `/apex/.../libc.so` 在某些 OEM 设备会 EACCES，此时回退 -1（Check skipped）。
- **Android 15+ (16 KB page)**：构建已启用 `-Wl,-z,max-page-size=16384`。

### Frida 版本

- 默认端口 27042、随机端口（`-l 0.0.0.0:0`）、`re.frida.helper`/`frida-server` 进程、D-Bus AUTH 探测、`frida-java-bridge`/`gum-js`/`quickjs` maps 签名、inline `LDR+BR` trampoline 8 字节签名都在覆盖范围内。
- 目标 Frida 主线版本：14.x – 16.x（2024 年的修订支持 16+ 随机端口与 D-Bus AUTH 探测）。

### 已知"看上去会检测、实际可能失效"的项

| 项目 | 失效场景 | 缓解 |
|---|---|---|
| D11 pagemap soft-dirty | untrusted_app 对 `/proc/self/pagemap` 多数返回 0 化 | 已并联 smaps + VMap 两路 |
| D11 smaps Private_Dirty | 部分 OEM 对 untrusted_app 隐藏脏页计数 | 同上 |
| D8 libc CRC | `/apex/.../libc.so` SELinux EACCES | 已用 dl_iterate_phdr 拿运行时路径；失败回退 -1（Check skipped）并由 GOT/匿名 RX 补充 |
| E5 `/data/adb/*` 路径 | untrusted_app 无读权限 | 不影响 root 设备；非 root 设备本就不应有这些路径 |
| D7 旧 `/system/lib*/libxposed*.so` 路径 | LSPosed 时代 Xposed 框架已不走该路径 | 已并联 LSPosed 路径 (`/data/adb/lspd`、`zygisk_lsposed`) |

### 设计上不做的事

- **不主动 `setuid`/`ptrace(PTRACE_TRACEME)` 反附加**：会与 ART debugger 冲突，且非主流风控做法。
- **不读 untrusted_app 不可访问的系统分区**：避免触 SELinux 拒绝事件，干扰运营日志。
- **不静默 root**：本工具只是检测器，不修改设备状态。

---

> 文档更新原则：每次新增/移除/调整一项检测，请同步修改本文对应小节与上方 [总体评分](#总体评分) 的合计；权重变动须同步 [`MainActivity.applyDebugScoreWeight`](../app/src/main/java/anti/rusda/MainActivity.java)。

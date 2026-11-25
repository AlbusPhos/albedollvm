# Changelog

本文件记录本项目所有值得关注的变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

> **版本号说明（0.x 阶段）**：在 1.0.0 发布之前，次版本号（`0.MINOR.0`）的变更
> 也可能包含破坏性改动，请留意标注为 **[BREAKING]** 的条目。

---

## [Unreleased]

### Added

- 新增 `BytesObfuscation` Pass（配置名 `bytes_obfuscation`，短名 `bo`），基于规则匹配
  LLVM IR 中的字节串常量，并调用 `obfstr2` 在编译期生成解密逻辑。
  - 支持三级混淆强度（`level = 1..=3`），规则可分别指定等级。
  - 支持三种预筛方式（互斥）：UTF-8 子串 `substrings`、Base64 字节子串
    `subbytesb64`、原始字节数组 `subbytesarr`；可叠加 `regex` 精确匹配。
  - 支持 `exclude = true` 排除规则，以及 `other_pct` / `other_level` 对未命中规则的
    字节串按概率抽样混淆。
- 新增 `BytesObfuscation` 的两种解密驻留方式：
  - **Lazy 静态堆模式**：解密函数签名为 `fn() -> *const u8`，使用 `OnceLock`
    将结果驻留于静态堆缓冲区。
  - **非 Lazy 栈模式**：解密函数签名为 `fn(out_buf: *mut u8, buf_len: usize) -> i32`，
    在调用点所在函数入口分配栈缓冲区并解密；按单函数 `stack_budget`
    以“混淆等级 / 字节长度 / 引用次数”为优先级贪心分配预算。
- 新增 `[bytes_obfuscation]` 配置段及 `[[bytes_obfuscation.rules]]` 规则数组
  （支持单数别名 `[[bytes_obfuscation.rule]]`），支持 `stack_budget`、`other_pct`、
  `other_level` 等参数，并对长度区间、混淆等级、预筛方式和正则做启动期校验。
- 新增 `rs2ir` 子系统，用于将 Rust 源码动态编译为 LLVM IR：
  - 按 `[rust_toolchain]` 调用 `cargo +<toolchain> rustc`，支持 `--target`
    与自定义 `--target-dir`。
  - 支持 `talc` / `libc` / `std` 三种临时单元内存分配器，`talc` 堆大小可配置。
  - 复用 `target_cache` 与按分配器区分的 `Cargo.lock` 缓存，降低重复依赖解析开销。
  - 使用 PID、原子序号与随机数生成唯一临时工程，配合 RAII 守卫清理源码、
    IR 与编译产物；串行化缓存读写以避免并发文件系统竞态。
- 新增 `[rust_toolchain]` 配置段，支持 `toolchain`、`target`、`target_dir`
  （别名 `build_dir`）、`allocator`、`talc_heap_size`（别名 `heap_size`）。
- 新增 `base64` 与 `memchr` 依赖，分别用于规则字节串解码和 SIMD 子串/符号扫描。
- 新增 `tests/test_bytes_obfuscation.rs` 与 `tests/demo/src/bytes.ll`，覆盖规则匹配、
  排除规则、PHI 节点替换、共享常量保留、`other_pct` 抽样、Pass 禁用及 Cargo 端到端验证；
  `tests/demo/atest` 增加 `--check-bo` 运行时自检。

### Changed

- `RemoveLeak` 的规则编译与校验从 Pass 运行时迁移至配置 `finalize()` 阶段：
  统一处理空规则名、`min_len`、无效 `max_len`、空正则和正则编译失败等场景，
  并使用 `memchr::memmem::Finder` 预构建 SIMD 子串搜索器、预编译字节正则。
- `RemoveLeak` 会根据最短预筛子串自动收紧 `min_len`，减少无效扫描；
  `[[remove_leak.rules]]` 现支持单数别名 `[[remove_leak.rule]]`。
- `TargetFunc` 符号解析改用 `memchr` / `memmem` / `memchr2` / `memrchr` 进行
  SIMD 扫描，降低大规模符号匹配开销；`[[target_func.rules]]` 现支持单数别名
  `[[target_func.rule]]`。
- 内部文件 `src/utils/conf/func.rs` 重命名为 `src/utils/conf/target_func.rs`，
  配置键 `[target_func]` 保持不变。
- `RustRemovePanic` 完成日志由 `debug` 级别调整为 `info`，便于在常规构建日志中
  确认 panic 函数清理与调用阻断结果。
- 测试工具统一将 `stderr` 合并到日志输出并启用彩色日志，便于失败时定位；
  `tests/demo/atest` 关闭 `strip = "symbols"` 并移除独立 workspace 声明，
  以适配端到端字节串检测。
- `Cargo.toml` 新增 `[profile.release]`：关闭调试信息、启用 LTO 与单 codegen unit，
  缩减插件体积并提升运行效率。

### Fixed

- 修复测试执行失败时仅输出 `stdout`、遗漏 `stderr` 诊断信息的问题。

### Security

- `[rust_toolchain]` 对 `toolchain`、`target`、`target_dir` 与 `talc_heap_size`
  做严格校验与安全回退，拒绝非法参数及 `..` 等路径穿越片段。
- `rs2ir` 在临时编译单元中清除 `RUSTFLAGS`、`RUSTC`、`RUSTC_WRAPPER` 等宿主环境变量，
  并使用独立临时目录，避免外部构建配置污染生成的 IR。

---

## [0.1.0] - 2026-11-22

### Added

- 首个公开版本：以 `cdylib` 形式提供 LLVM 树外 Pass 插件。
- `RemoveLeak`（`rl`）Pass：清理字符串常量中的主目录、Rust 标准库构建路径、
  源码路径、panic / backtrace 提示与 Tokio 运行时指纹。
- `RustRemovePanic`（`rp`）Pass：移除 Rust panic 函数体与直接调用点，
  支持 `trap` / `exit` 终止模式。
- 基于 TOML 的配置加载与合并机制，支持 `OLLVM_CONFIG`、工作目录 `ollvm.toml`
  及内置默认值。
- IR 级测试与 Cargo 端到端测试框架，覆盖同步与 Tokio 异步控制流。

---

[Unreleased]: https://github.com/AlbusPhos/albedollvm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AlbusPhos/albedollvm/commit/b8f54ae0c3b4c7c13a7ca7f3472062d72522da0a

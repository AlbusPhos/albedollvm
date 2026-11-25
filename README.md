<p align="center">
  <img src="assets/banner.svg" alt="Albedollvm — Rust LLVM hardening plugin" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MPL-2.0" src="https://img.shields.io/badge/license-MPL--2.0-3da639?"></a>
  <img alt="Rust 2024" src="https://img.shields.io/badge/rust-edition%202024-f74c00?">
  <img alt="LLVM 22" src="https://img.shields.io/badge/LLVM-22-5c6bc0?">
  <img alt="Status" src="https://img.shields.io/badge/status-experimental-f59e0b?">
</p>

<h1 align="center">Albedollvm</h1>

<p align="center">
  <strong>Rust 原生 LLVM 编译期加固和混淆插件</strong><br>
</p>

<p align="center">
  <code>RemoveLeak</code> · <code>RustRemovePanic</code> · <code>TOML</code> 配置 · 无运行时依赖
</p>

---

Albedollvm 是一个以 `cdylib` 形式构建的 LLVM 树外 Pass 插件，通过 rustc 的 `-Z llvm-plugins` 与 `-C passes=...` 接入 release 构建。它不修改源码、不引入运行时库，所有处理都发生在 LLVM IR 阶段。


> [!NOTE]
> 当前处于早期开发阶段。

## 设计目标/哲学

- **配置精确驱动** -- 通过toml配置精确配置混淆行为
- **非传统/标准混淆** -- 计划实现更多新颖的混淆方式
- **多态** -- 对抗tlsh等聚类方法

## Pass 一览

| Pass（短名）              | 作用                                                             |
|---------------------------|------------------------------------------------------------------|
| `RemoveLeak` (`rl`)       | 清理字符串常量中的路径、密钥、panic / backtrace 提示与运行时指纹 |
| `RustRemovePanic` (`rp`)  | 移除 Rust panic 函数体与直接调用点，按配置终止进程               |
| `BytesObfuscation` (`bo`) | 按规则匹配并混淆字节串常量，运行时解密                           |


## 配置

插件按以下顺序查找配置：

1. 环境变量 `OLLVM_CONFIG` 指向的文件
2. 当前工作目录下的 `ollvm.toml`
3. 都没有时使用内置默认值

示例：

```toml
[rust_toolchain]
toolchain = "1.98.0"                # 仅版本或通道：如 1.98.0 / nightly-2026-04-02 / stable
target = "x86_64-unknown-linux-gnu" # 可选，目标三元组：如 x86_64-unknown-linux-gnu / aarch64-apple-darwin
target_dir = "target"               # 可选，构建目录（亦支持别名 build_dir）：默认 "target"

[rust_remove_panic]
enabled = true
mode = "trap"
exit_code = 101

[remove_leak]
enabled = true
enable_builtins = true

[[remove_leak.rules]]
name = "InternalSecretKey"
min_len = 24
max_len = 256
substrings = ["sk-live-", "sk-test-"]
regex = '(sk-(?:live|test)-[0-9a-zA-Z]{16,64})'

[[target_func.rules]]
func = "mix64"
path = ["demo"]
pass = ["pass2", "pass3"]  # 对该函数应用这两个pass
exclude = false            # 控制是排除还是启用

[[target_func.rules]]
path = ["lib_unknown", "core"]
# 空pass表示应用全部pass

[[target_func.rules]]
func = "rpp64"
path = ["lib_unknown", "core"]
pass = ["pass3"]
exclude = true             # 在 core 中单独为 rpp64 排除 pass3

[target_func.pass1]        # 对其他未明确选择的函数按概率启用该pass
other_pct = 10             # 0..=100

[target_func.pass2]
other_pct = 0

[target_func.pass4]
other_pct = 100

[bytes_obfuscation]
enabled = true
other_pct = 0

[[bytes_obfuscation.rules]]
name = "BoE2ESecret"
min_len = 24
max_len = 256
substrings = ["sk-live-bo-e2e-"]
regex = 'sk-live-bo-e2e-[0-9a-f]{16}'
level = 2
```

## 测试

```bash
cargo test
```

测试覆盖两层：

- **IR 级测试**：通过 `opt-22` 加载插件、运行指定 Pass，检查输出 IR 与日志。
- **Cargo 端到端测试**：使用 `nightly-2026-04-02` + `-Z build-std` 编译 `tests/demo/atest`，验证同步 / Tokio 异步控制流、panic 终止与字符串擦除。


## 项目结构

```text
├── assets
│   └── banner.svg
├── Cargo.lock
├── Cargo.toml
├── CHANGELOG.md
├── LICENSE
├── ollvm.toml
├── README.md
├── src
│   ├── all_pass
│   │   ├── bytes_obfuscation.rs
│   │   ├── mod.rs
│   │   ├── remove_leak.rs
│   │   └── rust_remove_panic.rs
│   ├── lib.rs
│   └── utils
│       ├── conf
│       │   ├── bytes_obfuscation.rs
│       │   ├── remove_leak.rs
│       │   ├── rust_remove_panic.rs
│       │   ├── rust_toolchain.rs
│       │   └── target_func.rs
│       ├── conf.rs
│       ├── logger.rs
│       ├── mod.rs
│       ├── predicates.rs
│       └── rs2ir.rs
└── tests
    ├── common
    │   └── mod.rs
    ├── demo
    │   ├── atest
    │   │   ├── Cargo.lock
    │   │   ├── Cargo.toml
    │   │   └── src
    │   │       └── main.rs
    │   └── src
    │       ├── bytes.ll
    │       ├── leak.ll
    │       └── panic.ll
    ├── test_bytes_obfuscation.rs
    ├── test_remove_leak.rs
    └── test_rust_remove_panic.rs
```

## 许可证

本项目采用 [Mozilla Public License 2.0](LICENSE)（MPL-2.0）。


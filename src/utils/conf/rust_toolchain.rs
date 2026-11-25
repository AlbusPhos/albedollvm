// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// src/utils/conf/rust_toolchain.rs
use super::TAG;
use crate::pwarn;
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

/// 严格匹配合法的 Rust 工具链版本/通道名称（不含 target 后缀）：
/// - 通道：`stable`、`beta`、`nightly` 及日期版本 `nightly-2026-04-02`
/// - 版本：`1.98`、`1.98.0`
static TOOLCHAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:stable|beta|nightly)(?:-\d{4}-\d{2}-\d{2})?|\d+\.\d+(?:\.\d+)?)$")
        .expect("内置 TOOLCHAIN_REGEX 正则编译失败")
});

/// 严格匹配合法的 Rust / LLVM Target Triple（2~4 段，如 `x86_64-unknown-linux-gnu`、`wasm32-wasip1`）
static TARGET_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]*-[a-zA-Z][a-zA-Z0-9_]*(?:-[a-zA-Z][a-zA-Z0-9_.]*){0,2}$")
        .expect("内置 TARGET_REGEX 正则编译失败")
});

/// 严格匹配合法的相对构建目录路径字符（禁止以 `-` 或 `/` 开头，如 `target`、`target/llvm-ir`、`.cache/target`）
static TARGET_DIR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9_.][a-zA-Z0-9_.\-/]*$").expect("内置 TARGET_DIR_REGEX 正则编译失败")
});

/// `[rust_toolchain]` 顶层配置
///
/// 示例：
/// ```toml
/// [rust_toolchain]
/// toolchain = "1.98.0"                # 仅版本或通道：如 1.98.0 / nightly-2026-04-02 / stable
/// target = "x86_64-unknown-linux-gnu" # 可选，目标三元组：如 x86_64-unknown-linux-gnu / aarch64-apple-darwin
/// target_dir = "target"               # 可选，构建目录（亦支持别名 build_dir）：默认 "target"
/// allocator = "talc"                  # 可选，内存分配器（"talc" | "libc" | "std"）：默认 "talc"
/// talc_heap_size = 4_194_304          # 可选，talc 静态堆大小（字节，亦支持别名 heap_size）：默认 4 MiB
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RustToolchainConfig {
    /// 用于 `rs2ir` 动态生成 LLVM IR 的 Rust 工具链版本（需要与当前 llvm-pass 版本匹配）
    pub toolchain: String,
    /// 可选：目标平台三元组（`--target`）
    pub target: Option<String>,
    /// 可选：构建目录（`--target-dir`），默认 `"target"`
    #[serde(alias = "build_dir")]
    pub target_dir: String,
    /// 可选：内存分配器策略（`"talc"` | `"libc"` | `"std"`），默认 `"talc"`
    pub allocator: Allocator,
    /// 可选：`talc` 分配器的静态堆空间大小（单位：字节，亦支持别名 `heap_size`），默认 4 MiB (`4_194_304`)
    #[serde(alias = "heap_size")]
    pub talc_heap_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Allocator {
    #[default]
    Talc,
    Libc,
    Std,
}

impl Default for RustToolchainConfig {
    fn default() -> Self {
        Self {
            toolchain: default_toolchain(),
            target: None,
            target_dir: default_target_dir(),
            allocator: Allocator::default(),
            talc_heap_size: default_talc_heap_size(),
        }
    }
}

impl RustToolchainConfig {
    /// 允许配置的最小 `talc` 静态堆大小：4 KiB
    pub const MIN_TALC_HEAP_SIZE: usize = 4 * 1024;
    /// 允许配置的最大 `talc` 静态堆大小：1 GiB
    pub const MAX_TALC_HEAP_SIZE: usize = 1024 * 1024 * 1024;
    /// 默认的 `talc` 静态堆大小：4 MiB
    pub const DEFAULT_TALC_HEAP_SIZE: usize = 4 * 1024 * 1024;

    pub(super) fn finalize(&mut self) {
        let trimmed_tc = self.toolchain.trim().trim_start_matches('+');
        if trimmed_tc.is_empty() {
            self.toolchain = default_toolchain();
        } else if !Self::is_valid_toolchain(trimmed_tc) {
            let fallback = default_toolchain();
            pwarn!(
                TAG,
                "[rust_toolchain] toolchain = '{}' 未通过版本正则校验（请勿混入 target 后缀），已回退为 '{}'。",
                self.toolchain,
                fallback
            );
            self.toolchain = fallback;
        } else if trimmed_tc.len() != self.toolchain.len() {
            self.toolchain = trimmed_tc.to_owned();
        }

        if let Some(raw_target) = &self.target {
            let trimmed_target = raw_target.trim();
            if trimmed_target.is_empty() {
                self.target = None;
            } else if !Self::is_valid_target(trimmed_target) {
                let fallback = None;
                pwarn!(
                    TAG,
                    "[rust_toolchain] target = '{}' 未通过目标三元组正则校验，已回退为 {:?}。",
                    raw_target,
                    fallback
                );
                self.target = fallback;
            } else if trimmed_target.len() != raw_target.len() {
                self.target = Some(trimmed_target.to_owned());
            }
        }

        let trimmed_dir = self.target_dir.trim();
        if trimmed_dir.is_empty() {
            self.target_dir = default_target_dir();
        } else {
            let normalized_dir = trimmed_dir.trim_end_matches('/');
            if !Self::is_valid_target_dir(normalized_dir) {
                let fallback = default_target_dir();
                pwarn!(
                    TAG,
                    "[rust_toolchain] target_dir = '{}' 未通过构建目录安全校验（请使用安全的相对路径），已回退为 '{}'。",
                    self.target_dir,
                    fallback
                );
                self.target_dir = fallback;
            } else if normalized_dir.len() != self.target_dir.len() {
                self.target_dir = normalized_dir.to_owned();
            }
        }

        if !Self::is_valid_talc_heap_size(self.talc_heap_size) {
            let fallback = default_talc_heap_size();
            pwarn!(
                TAG,
                "[rust_toolchain] talc_heap_size = {} 超出安全范围（{} ~ {} 字节），已回退为 {}。",
                self.talc_heap_size,
                Self::MIN_TALC_HEAP_SIZE,
                Self::MAX_TALC_HEAP_SIZE,
                fallback
            );
            self.talc_heap_size = fallback;
        }
    }

    /// 获取已通过校验的工具链版本标识符（不含前导 `+`，如 `"1.98.0"`）
    #[inline]
    pub fn toolchain(&self) -> &str {
        &self.toolchain
    }

    /// 获取已通过校验的目标三元组（如 `Some("x86_64-unknown-linux-gnu")`）
    #[inline]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// 获取已通过校验的构建目录（默认 `"target"`）
    #[inline]
    pub fn target_dir(&self) -> &str {
        &self.target_dir
    }

    /// 获取已通过校验的分配器类型（`"talc"` | `"libc"` | `"std"`）
    #[inline]
    pub fn allocator(&self) -> Allocator {
        self.allocator
    }

    /// 获取已通过校验的 `talc` 静态堆空间大小（单位：字节，默认 4 MiB）
    #[inline]
    pub fn talc_heap_size(&self) -> usize {
        self.talc_heap_size
    }

    /// 判断当前分配器配置是否为 `no_std` 模式（即 `"talc"` 或 `"libc"`）
    #[inline]
    pub fn is_no_std(&self) -> bool {
        matches!(self.allocator, Allocator::Libc | Allocator::Talc)
    }

    /// 获取供 `cargo +<toolchain>` 或 `rustc +<toolchain>` 使用的参数
    #[inline]
    pub fn plus_arg(&self) -> String {
        format!("+{}", self.toolchain)
    }

    /// 校验是否为纯工具链版本/通道名
    #[inline]
    pub fn is_valid_toolchain(s: &str) -> bool {
        TOOLCHAIN_REGEX.is_match(s)
    }

    /// 校验是否为合法的 Target Triple（严格排除通道名前缀）
    #[inline]
    pub fn is_valid_target(s: &str) -> bool {
        !s.starts_with("stable-")
            && !s.starts_with("beta-")
            && !s.starts_with("nightly-")
            && TARGET_REGEX.is_match(s)
    }

    /// 校验是否为合法且安全的相对构建目录
    #[inline]
    pub fn is_valid_target_dir(s: &str) -> bool {
        TARGET_DIR_REGEX.is_match(s)
            && !s
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    }

    /// 校验是否为合法的分配器选项（`"talc"` | `"libc"` | `"std"`）
    #[inline]
    pub fn is_valid_allocator(s: &str) -> bool {
        matches!(s, "talc" | "libc" | "std")
    }

    /// 校验是否为合法的 `talc` 堆大小（`4 KiB <= size <= 1 GiB`）
    #[inline]
    pub fn is_valid_talc_heap_size(size: usize) -> bool {
        (Self::MIN_TALC_HEAP_SIZE..=Self::MAX_TALC_HEAP_SIZE).contains(&size)
    }
}

fn default_toolchain() -> String {
    "stable".to_owned()
}

fn default_target_dir() -> String {
    "target".to_owned()
}

fn default_talc_heap_size() -> usize {
    RustToolchainConfig::DEFAULT_TALC_HEAP_SIZE
}

#[cfg(test)]
mod tests {
    use crate::utils::conf::remove_leak::RemoveLeakConfig;
    use super::*;

    #[test]
    fn test_valid_toolchains() {
        let valid_cases = [
            "1.98.0",
            "1.98",
            "stable",
            "beta",
            "nightly",
            "nightly-2026-04-02",
            "+nightly-2026-04-02",
        ];
        for case in valid_cases {
            let mut cfg = RustToolchainConfig {
                toolchain: case.to_owned(),
                ..Default::default()
            };
            cfg.finalize();
            assert_eq!(cfg.toolchain(), case.trim_start_matches('+'));
            assert_eq!(cfg.target_dir(), "target");
            assert_eq!(
                cfg.talc_heap_size(),
                RustToolchainConfig::DEFAULT_TALC_HEAP_SIZE
            );
        }
    }

    #[test]
    fn test_valid_targets() {
        let valid_targets = [
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-apple-darwin",
            "aarch64-linux-android",
            "wasm32-unknown-unknown",
            "wasm32-wasip1",
            "riscv64gc-unknown-none-elf",
            "thumbv7em-none-eabihf",
        ];
        for t in valid_targets {
            let mut cfg = RustToolchainConfig {
                toolchain: "1.98.0".to_owned(),
                target: Some(t.to_owned()),
                ..Default::default()
            };
            cfg.finalize();
            assert_eq!(cfg.target(), Some(t));
        }
    }

    #[test]
    fn test_valid_target_dirs() {
        let valid_dirs = [
            ("target", "target"),
            ("build", "build"),
            ("target/llvm-ir", "target/llvm-ir"),
            (".cache/rs2ir_target", ".cache/rs2ir_target"),
            ("  target/custom/  ", "target/custom"),
            ("", "target"), // 空串自动回退为默认 "target"
        ];
        for (input, expected) in valid_dirs {
            let mut cfg = RustToolchainConfig {
                target_dir: input.to_owned(),
                ..Default::default()
            };
            cfg.finalize();
            assert_eq!(cfg.target_dir(), expected);
        }
    }

    #[test]
    fn test_valid_and_fallback_talc_heap_sizes() {
        let valid_sizes = [
            RustToolchainConfig::MIN_TALC_HEAP_SIZE,
            64 * 1024,
            1024 * 1024,
            16 * 1024 * 1024,
            RustToolchainConfig::MAX_TALC_HEAP_SIZE,
        ];
        for size in valid_sizes {
            let mut cfg = RustToolchainConfig {
                talc_heap_size: size,
                ..Default::default()
            };
            cfg.finalize();
            assert_eq!(cfg.talc_heap_size(), size);
        }

        let invalid_sizes = [
            0,
            1,
            RustToolchainConfig::MIN_TALC_HEAP_SIZE - 1,
            RustToolchainConfig::MAX_TALC_HEAP_SIZE + 1,
            usize::MAX,
        ];
        for bad_size in invalid_sizes {
            assert!(!RustToolchainConfig::is_valid_talc_heap_size(bad_size));
            let mut cfg = RustToolchainConfig {
                talc_heap_size: bad_size,
                ..Default::default()
            };
            cfg.finalize();
            assert_eq!(
                cfg.talc_heap_size(),
                RustToolchainConfig::DEFAULT_TALC_HEAP_SIZE
            );
        }
    }

    #[test]
    fn test_strict_separation_between_toolchain_and_target() {
        for tc in [
            "1.98.0",
            "1.98",
            "stable",
            "beta",
            "nightly",
            "nightly-2026-04-02",
        ] {
            assert!(RustToolchainConfig::is_valid_toolchain(tc));
            assert!(
                !RustToolchainConfig::is_valid_target(tc),
                "toolchain '{tc}' 不应通过 target 校验"
            );
        }
        for target in [
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-apple-darwin",
            "wasm32-wasip1",
        ] {
            assert!(RustToolchainConfig::is_valid_target(target));
            assert!(
                !RustToolchainConfig::is_valid_toolchain(target),
                "target '{target}' 不应通过 toolchain 校验"
            );
        }
        for mixed in [
            "stable-x86_64-unknown-linux-gnu",
            "1.98.0-x86_64-pc-windows-msvc",
            "nightly-2026-04-02-aarch64-apple-darwin",
        ] {
            assert!(
                !RustToolchainConfig::is_valid_toolchain(mixed),
                "混合串 '{mixed}' 不应通过 toolchain 校验"
            );
            assert!(
                !RustToolchainConfig::is_valid_target(mixed),
                "混合串 '{mixed}' 不应通过 target 校验"
            );
        }
    }

    #[test]
    fn test_reject_command_and_argument_injection() {
        let malicious_cases = [
            "1.98.0; rm -rf /",
            "stable && calc.exe",
            "x86_64-unknown-linux-gnu; id",
            "$(whoami)",
            "`id`",
            "--version",
            "--target=x86_64-unknown-linux-gnu",
            "-C",
            "../my-toolchain",
            "nightly-2026-04-2", // 日期格式错误
            "custom_arbitrary_name",
        ];
        for bad in malicious_cases {
            assert!(
                !RustToolchainConfig::is_valid_toolchain(bad),
                "应当拦截非法 toolchain 输入: {bad}"
            );
            assert!(
                !RustToolchainConfig::is_valid_target(bad),
                "应当拦截非法 target 输入: {bad}"
            );
            assert!(
                !RustToolchainConfig::is_valid_allocator(bad),
                "应当拦截非法 allocator 输入: {bad}"
            );
        }
        let malicious_dirs = [
            "target; rm -rf /",
            "target && calc.exe",
            "$(whoami)",
            "`id`",
            "--target-dir=/tmp",
            "-C",
            "/",
            "/etc/passwd",
            ".",
            "..",
            "../outside",
            "target/../outside",
            "target/./sub",
            "target//sub",
        ];
        for bad_dir in malicious_dirs {
            assert!(
                !RustToolchainConfig::is_valid_target_dir(bad_dir),
                "应当拦截非法 target_dir 输入: {bad_dir}"
            );
        }
    }
}
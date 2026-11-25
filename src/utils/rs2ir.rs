// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// src/utils/rs2ir.rs

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use lib_unknown::rand::core::random;

use super::conf::{
    CONFIG,
    rust_toolchain::{Allocator, RustToolchainConfig},
};
use crate::{pdebug, pwarn};

const TAG: &str = "RS2IR";
static C: AtomicUsize = AtomicUsize::new(0);
/// 保护共享 `target_cache` 目录，防止并发 `cargo` 扫描与清理线程发生文件系统竞态
static TARGET_CACHE_LOCK: Mutex<()> = Mutex::new(());

const DEFAULT_DEP: &str = r#"obfstr2 = { version = "=0.5.3", features = ["force_heap"] }"#;

/// 根据工具链配置生成对应的 `Cargo.toml` 依赖项、`src/lib.rs` 头部代码及锁缓存标识
fn build_allocator_parts(tc_cfg: &RustToolchainConfig) -> (String, String, &'static str) {
    match tc_cfg.allocator() {
        Allocator::Talc => {
            let heap_size = tc_cfg.talc_heap_size();
            let deps = format!("{DEFAULT_DEP}\ntalc = \"5.1.1\"\nspinning_top = \"0.3\"");
            let header = format!(
                r#"#![no_std]
#![cfg(not(test))]
extern crate alloc;
use core::panic::PanicInfo;
use spinning_top::RawSpinlock;
use talc::{{DefaultBinning, TalcLock, min_first_heap_size, source::Claim}};
const __TALC_HEAP_SIZE: usize = min_first_heap_size::<DefaultBinning>() + {heap_size};
#[global_allocator]
static __GLOBAL_ALLOCATOR: TalcLock<RawSpinlock, Claim> = TalcLock::new(unsafe {{
    static mut __INITIAL_HEAP: [u8; __TALC_HEAP_SIZE] = [0; __TALC_HEAP_SIZE];
    Claim::array(&raw mut __INITIAL_HEAP)
}});
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {{
    loop {{}}
}}
"#
            );
            (deps, header, "talc")
        }
        Allocator::Libc => {
            let deps = format!("{DEFAULT_DEP}\nlibc_alloc = \"1.0\"");
            let header = r#"#![no_std]
#![cfg(not(test))]
extern crate alloc;
use core::panic::PanicInfo;
#[global_allocator]
static __GLOBAL_ALLOCATOR: libc_alloc::LibcAlloc = libc_alloc::LibcAlloc;
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
"#
            .to_owned();
            (deps, header, "libc")
        }
        Allocator::Std => {
            let deps = DEFAULT_DEP.to_owned();
            let header = r#"#![cfg(not(test))]
extern crate alloc;
"#
            .to_owned();
            (deps, header, "std")
        }
    }
}

pub fn to_byte_literal(bytes: &[u8]) -> String {
    let mut lit = String::with_capacity(bytes.len() * 2 + 3);
    lit.push_str("b\"");
    for &b in bytes {
        for esc in std::ascii::escape_default(b) {
            lit.push(esc as char);
        }
    }
    lit.push('"');
    lit
}

pub fn bytes2fn(bytes: &[u8], level: u8, lazy: bool) -> (String, String, bool) {
    let c = C.fetch_add(1, Ordering::Relaxed);
    let func = format!("_llvm_bytes_{c}_{}", random::<usize>());
    let len = bytes.len();
    let bytes_lit = to_byte_literal(bytes);
    let mut code = String::with_capacity(386 + bytes_lit.len());
    if lazy {
        let _ = write!(
            code,
            r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn {func}() -> *const u8 {{
    static S: obfstr2::lazy::OnceLock<obfstr2::types::buffer::HeapBuffer<u8, {len}>> =
        obfstr2::lazy::OnceLock::new();
    S.call_once(|| obfstr2::b{level}!({bytes_lit})).as_ptr()
}}
"#
        );
    } else {
        let _ = write!(
            code,
            r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn {func}(out_buf: *mut u8, buf_len: usize) -> i32 {{
    if out_buf.is_null() || buf_len < {len} {{
        return -1;
    }}
    let tmp = obfstr2::b{level}!({bytes_lit});
    unsafe {{
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), out_buf, {len});
    }}
    0
}}
"#
        );
    }
    (code, func, lazy)
}

/// 将传入的 Rust 函数源码数组组装为编译单元，并按配置的分配器策略编译为优化后的 LLVM IR
pub fn to_ir<S: AsRef<str>>(fns: &[S]) -> Result<String, String> {
    if fns.is_empty() {
        let msg = "待编译的 Rust 函数列表不能为空".to_string();
        pwarn!(TAG, "{}", msg);
        return Err(msg);
    }

    let pid = std::process::id();
    let c = C.fetch_add(1, Ordering::Relaxed);
    let tc_cfg = &CONFIG.rust_toolchain;
    let (deps, lib_header, alloc_tag) = build_allocator_parts(tc_cfg);

    let raw_build_dir = Path::new(tc_cfg.target_dir());
    if let Err(err) = fs::create_dir_all(raw_build_dir) {
        let msg = format!("无法创建构建根目录 {}: {}", raw_build_dir.display(), err);
        pwarn!(TAG, "{}", msg);
        return Err(msg);
    }

    let build_dir = fs::canonicalize(raw_build_dir).map_err(|err| {
        let msg = format!(
            "无法解析构建目录绝对路径 {}: {}",
            raw_build_dir.display(),
            err
        );
        pwarn!(TAG, "{}", msg);
        msg
    })?;

    // 结合 PID、原子序号与随机数，确保跨进程与多线程下的绝对唯一性
    let unit = format!("ir_unit_{pid}_{c}_{}", random::<usize>());
    let poj = build_dir.join(&unit);
    let src_dir = poj.join("src");
    let manifest_path = poj.join("Cargo.toml");
    let ll_path = poj.join("out.ll");
    let shared_target_dir = build_dir.join("target_cache");
    let lock_cache_path = shared_target_dir.join(format!("Cargo.lock.{alloc_tag}.cache"));

    if let Err(err) = fs::create_dir_all(&src_dir) {
        let msg = format!("无法创建临时工程目录 {}: {}", src_dir.display(), err);
        pwarn!(TAG, "{}", msg);
        return Err(msg);
    }

    // 外层 RAII 守卫：在函数退出时无锁清理线程私有的临时工程目录 poj
    let _poj_cleanup = PojCleanupGuard { poj_dir: &poj };

    let cargo_toml = format!(
        r#"[package]
name = "{unit}"
version = "0.1.0"
edition = "2024"
[lib]
crate-type = ["staticlib"]
[dependencies]
{deps}
[profile.release]
debug = 0
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
incremental = false
"#
    );
    if let Err(err) = fs::write(&manifest_path, cargo_toml) {
        let msg = format!("写入 Cargo.toml 失败: {}", err);
        pwarn!(TAG, "{}", msg);
        return Err(msg);
    }

    // 组装完整的 src/lib.rs 源码
    let total_fn_len: usize = fns.iter().map(|f| f.as_ref().len() + 1).sum();
    let mut code = String::with_capacity(lib_header.len() + total_fn_len);
    code.push_str(&lib_header);
    for f in fns {
        code.push_str(f.as_ref());
        code.push('\n');
    }
    if let Err(err) = fs::write(src_dir.join("lib.rs"), code) {
        let msg = format!("写入 src/lib.rs 失败: {}", err);
        pwarn!(TAG, "{}", msg);
        return Err(msg);
    }

    // 确定本次编译产物所在的 release 目录
    let release_dir = match tc_cfg.target() {
        Some(triple) => shared_target_dir.join(triple).join("release"),
        None => shared_target_dir.join("release"),
    };

    // 组装命令: cargo +<toolchain> rustc --release [--target <triple>] -- --emit=llvm-ir=<ll_path>
    let mut cmd = Command::new("cargo");
    cmd.arg(tc_cfg.plus_arg())
        .arg("rustc")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest_path);
    if let Some(triple) = tc_cfg.target() {
        cmd.arg("--target").arg(triple);
    }
    // 显式指定 .ll 输出路径（输出在私有的 poj 目录下），不受不同版本 Cargo 的布局影响
    cmd.arg("--")
        .arg(format!("--emit=llvm-ir={}", ll_path.display()));
    cmd.current_dir(&poj)
        .env("CARGO_TARGET_DIR", &shared_target_dir)
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO_MAKEFLAGS");

    // 临界区：串行化访问 shared_target_dir，保证编译、Cargo.lock 缓存读写与产物清理互不踩踏
    {
        let _lock = TARGET_CACHE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 内层 RAII 守卫：在离开此作用域（释放 _lock 锁）前，立即清理 shared_target_dir 下本次生成的单元产物
        let _target_cleanup = TargetCleanupGuard {
            release_dir: &release_dir,
            unit_prefix: &unit,
        };

        // 若存在已缓存的 Cargo.lock，直接复刻以避免重复解析依赖图
        let poj_lock = poj.join("Cargo.lock");
        if lock_cache_path.is_file() {
            let _ = fs::copy(&lock_cache_path, &poj_lock);
        }

        pdebug!(
            TAG,
            "开始编译临时 IR 单元: {} (toolchain={},allocator={})",
            unit,
            tc_cfg.toolchain(),
            alloc_tag
        );

        let output = cmd.output().map_err(|err| {
            let msg = format!("调用 cargo ({}) 失败: {}", tc_cfg.plus_arg(), err);
            pwarn!(TAG, "{}", msg);
            msg
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = format!(
                "编译临时 IR 单元 {} 失败 (status={}):\n{}",
                unit, output.status, stderr
            );
            pwarn!(TAG, "{}", msg);
            return Err(msg);
        }

        // 编译成功后，若对应分配器的全局 Cargo.lock 缓存尚不存在，则通过同目录原子重命名写入缓存
        if !lock_cache_path.exists() && poj_lock.is_file() {
            let tmp_lock = shared_target_dir.join(format!("Cargo.lock.{alloc_tag}.tmp.{unit}"));
            if fs::copy(&poj_lock, &tmp_lock).is_ok() {
                let _ = fs::rename(&tmp_lock, &lock_cache_path);
                let _ = fs::remove_file(&tmp_lock);
            }
        }
        // 此处 _target_cleanup 先于 _lock 析构，在持锁状态下安全清理 release_dir 中的本单元产物
    }

    // 锁外并行读取私有目录下的 .ll 文件
    match fs::read_to_string(&ll_path) {
        Ok(ir) => {
            pdebug!(
                TAG,
                "成功生成 LLVM IR: {} (bytes={})",
                ll_path.display(),
                ir.len()
            );
            Ok(ir)
        }
        Err(err) => {
            let msg = format!("读取生成的 IR 文件 {} 失败: {}", ll_path.display(), err);
            pwarn!(TAG, "{}", msg);
            Err(msg)
        }
    }
}

/// 严格校验文件名是否属于当前编译单元的产物（前缀后必须为结尾、`'-'` 或 `'.'`）
#[inline]
fn is_unit_artifact(file_name: &str, prefix: &str) -> bool {
    file_name
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('-') || rest.starts_with('.'))
}

/// 负责在 `to_ir` 结束时清理线程私有的临时源码目录（包含 src/、Cargo.toml 及 out.ll）
struct PojCleanupGuard<'a> {
    poj_dir: &'a Path,
}

impl Drop for PojCleanupGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.poj_dir);
    }
}

/// 负责在持有 `TARGET_CACHE_LOCK` 期间清理 `target_cache` 下与当前单元相关的编译产物
struct TargetCleanupGuard<'a> {
    release_dir: &'a Path,
    unit_prefix: &'a str,
}

impl Drop for TargetCleanupGuard<'_> {
    fn drop(&mut self) {
        let lib_prefix = format!("lib{}", self.unit_prefix);
        let subdirs = [
            self.release_dir.to_path_buf(),
            self.release_dir.join("deps"),
            self.release_dir.join("build"),
            self.release_dir.join(".fingerprint"),
        ];

        for dir in subdirs {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && (is_unit_artifact(name, self.unit_prefix)
                        || is_unit_artifact(name, &lib_prefix))
                {
                    if path.is_dir() {
                        let _ = fs::remove_dir_all(path);
                    } else {
                        let _ = fs::remove_file(path);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_byte_literal() {
        assert_eq!(to_byte_literal(b"hello"), r#"b"hello""#);
        assert_eq!(to_byte_literal(b"say \"hi\"\n"), r#"b"say \"hi\"\n""#);
        assert_eq!(to_byte_literal(&[0x00, 0x01, 0xFF]), r#"b"\x00\x01\xff""#);
        assert_eq!(to_byte_literal(b""), r#"b"""#);
    }

    #[test]
    fn test_is_unit_artifact() {
        let prefix = "ir_unit_100_1_99";
        assert!(is_unit_artifact("ir_unit_100_1_99", prefix));
        assert!(is_unit_artifact("ir_unit_100_1_99.d", prefix));
        assert!(is_unit_artifact("ir_unit_100_1_99-a1b2c3d4.rlib", prefix));
        assert!(!is_unit_artifact("ir_unit_100_1_990.d", prefix));
        assert!(!is_unit_artifact("ir_unit_100_1_99_extra", prefix));
    }

    #[test]
    fn test_to_ir_end_to_end() {
        let (fn_code, fn_name, _) = bytes2fn(b"secret_ke7y_12345\0", 1, true);
        let raw_fn = r#"
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn straaa(out_buf: *mut u8, buf_len: usize) -> i32 {
    if out_buf.is_null() || buf_len < 4 {
        return -1;
    }
    let tmp = obfstr2::b1!(b"test");
    unsafe {
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), out_buf, 4);
    }
    0
}
"#;
        let ir = to_ir(&[fn_code.as_str(), raw_fn]).expect("应当成功生成 LLVM IR");
        println!("{}", ir);
        assert!(
            ir.contains(&fn_name),
            "生成的 LLVM IR 应当包含导出函数符号 {}",
            fn_name
        );
        assert!(
            ir.contains("straaa"),
            "生成的 LLVM IR 应当包含导出函数符号 straaa"
        );
    }

    #[test]
    fn test_to_ir_concurrent() {
        std::thread::scope(|s| {
            let mut handles = Vec::new();
            for i in 0..4 {
                handles.push(s.spawn(move || {
                    let payload = format!("concurrent_secret_{i}\0");
                    let (fn_code, fn_name, _) = bytes2fn(payload.as_bytes(), 1, i % 2 == 0);
                    let ir = to_ir(&[fn_code.as_str()]).expect("并发生成 LLVM IR 应当成功");
                    assert!(
                        ir.contains(&fn_name),
                        "线程 {i} 生成的 IR 应当包含符号 {fn_name}"
                    );
                }));
            }
            for h in handles {
                h.join().expect("工作线程不应发生 panic");
            }
        });
    }
}

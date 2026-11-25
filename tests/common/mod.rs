// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// tests/common/mod.rs
#![allow(dead_code)]

use llvm_pass::LLVM_VERSION_MAJOR;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

static PLUGIN_DYLIB_PATH: OnceLock<PathBuf> = OnceLock::new();
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn demo_src(file_name: &str) -> PathBuf {
    manifest_dir().join("tests/demo/src").join(file_name)
}

pub fn demo_atest_dir() -> PathBuf {
    manifest_dir().join("tests/demo/atest")
}

pub fn default_target() -> &'static str {
    if cfg!(target_os = "windows") {
        "x86_64-pc-windows-gnullvm"
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

/// 编译 albedollvm 插件（整个测试生命周期仅编译一次）
pub fn get_plugin_dylib() -> &'static Path {
    PLUGIN_DYLIB_PATH.get_or_init(|| {
        let root = manifest_dir();
        let target_dir = root.join(format!("target/test-plugin-llvm{LLVM_VERSION_MAJOR}"));

        let status = Command::new(env!("CARGO"))
            .args(["build", "--release", "--lib"])
            .arg("--manifest-path")
            .arg(root.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .status()
            .expect("Failed to invoke cargo to build albedollvm");
        assert!(status.success(), "Failed to build albedollvm plugin");

        let dylib_name = format!(
            "{}albedollvm.{}",
            env::consts::DLL_PREFIX,
            env::consts::DLL_EXTENSION
        );
        let dylib_path = target_dir.join("release").join(dylib_name);
        assert!(
            dylib_path.exists(),
            "Plugin dylib not found at {:?}",
            dylib_path
        );
        dylib_path
    })
}

fn temp_file(prefix: &str, ext: &str) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    env::temp_dir().join(format!("albedollvm_{prefix}_{pid}_{id}.{ext}"))
}

/// 使用 `opt-<LLVM_VERSION_MAJOR>` 运行指定 Pass 与临时 TOML 配置，返回 (输出 IR, 插件日志)
pub fn run_opt(ir_file_name: &str, passes: &str, toml_content: &str) -> (String, String) {
    let plugin = get_plugin_dylib();
    let ir_file = demo_src(ir_file_name);
    let opt_bin = format!("opt-{LLVM_VERSION_MAJOR}");

    let cfg_file = temp_file("cfg", "toml");
    let out_ir_file = temp_file("out", "ll");
    fs::write(&cfg_file, toml_content).expect("write temp config");

    let output = Command::new(&opt_bin)
        .env("OLLVM_CONFIG", &cfg_file)
        .env("OLLVM_LOG_LEVEL", "DEBUG")
        .env("OLLVM_LOG_COLOR", "always")
        .arg(format!("-load-pass-plugin={}", plugin.display()))
        .arg(format!("-passes={passes}"))
        .arg("-S")
        .arg("-o")
        .arg(&out_ir_file)
        .arg(&ir_file)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {opt_bin}: {e}"));

    let _ = fs::remove_file(&cfg_file);

    let mut stdout_logs = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        stdout_logs.push_str(&stderr);
    }
    assert!(
        output.status.success(),
        "`{opt_bin}` failed:\nlogs:\n{stdout_logs}"
    );

    let ir_out = fs::read_to_string(&out_ir_file).expect("read output IR");
    let _ = fs::remove_file(&out_ir_file);

    (ir_out, stdout_logs)
}

/// 使用指定的 passes 和可选的自定义 TOML 配置编译 `tests/demo/atest` 真实工程，返回编译后的二进制路径
pub fn build_demo_atest(suite_tag: &str, passes: &str, custom_toml: Option<&str>) -> PathBuf {
    let root = manifest_dir();
    let atest_dir = demo_atest_dir();
    let plugin = get_plugin_dylib();
    let target = env::var("OLLVM_TEST_TARGET").unwrap_or_else(|_| default_target().to_string());

    let target_dir = root.join(format!("target/test-atest-{suite_tag}"));

    let cfg_path = match custom_toml {
        Some(content) => {
            let p = temp_file(suite_tag, "toml");
            fs::write(&p, content).expect("write custom toml");
            p
        }
        None => root.join("ollvm.toml"),
    };

    let stamp_file = target_dir.join(".plugin_stamp");
    let plugin_mtime = fs::metadata(plugin).and_then(|m| m.modified()).ok();
    let stamp_mtime = fs::metadata(&stamp_file).and_then(|m| m.modified()).ok();

    if plugin_mtime != stamp_mtime {
        let _ = fs::remove_dir_all(&target_dir);
        fs::create_dir_all(&target_dir).expect("create target_dir");
    } else {
        let _ = Command::new("cargo")
            .args([
                "+nightly-2026-04-02",
                "clean",
                "-p",
                "atest",
                "--release",
                "--target",
                &target,
            ])
            .arg("--target-dir")
            .arg(&target_dir)
            .current_dir(&atest_dir)
            .status();
    }

    let target_feature = if cfg!(target_os = "windows") {
        " -C target-feature=+crt-static"
    } else {
        ""
    };
    let rustflags = format!(
        "-Z llvm-plugins={} -C passes={}{}",
        plugin.display(),
        passes,
        target_feature
    );

    let status = Command::new("cargo")
        .args([
            "+nightly-2026-04-02",
            "build",
            "-Z",
            "build-std=std,panic_abort,core,alloc",
            "--release",
            "--target",
            &target,
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(&atest_dir)
        .env_remove("RUSTC_WRAPPER")
        .env("OLLVM_CONFIG", &cfg_path)
        .env("OLLVM_LOG_LEVEL", "INFO")
        .env("OLLVM_LOG_COLOR", "always")
        .env("RUSTFLAGS", &rustflags)
        .status()
        .expect("Failed to execute cargo +nightly build for demo/atest");

    if let Some(mtime) = plugin_mtime {
        if let Ok(f) = fs::File::create(&stamp_file) {
            let _ = f.set_modified(mtime);
        }
    }

    if custom_toml.is_some() {
        let _ = fs::remove_file(&cfg_path);
    }

    assert!(
        status.success(),
        "Building demo/atest with passes={passes} failed"
    );

    let bin_name = format!("atest{}", env::consts::EXE_SUFFIX);
    let bin_path = target_dir.join(&target).join("release").join(bin_name);
    assert!(
        bin_path.exists(),
        "Compiled binary not found: {:?}",
        bin_path
    );
    bin_path
}

// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// tests/test_bytes_obfuscation.rs

mod common;

use std::fs;
use std::process::Command;

#[test]
fn test_bo_opt_rules_phi_and_verify() {
    let toml = r#"
        [rust_toolchain]
        toolchain = "nightly-2026-04-02"

        [bytes_obfuscation]
        enabled = true
        other_pct = 0
        other_level = 1

        [[bytes_obfuscation.rules]]
        name = "InternalSecretKey"
        min_len = 24
        max_len = 256
        substrings = ["sk-live-", "sk-test-"]
        regex = 'sk-(?:live|test)-[0-9a-zA-Z]{16,64}'
        exclude = false
        level = 3

        [[bytes_obfuscation.rules]]
        name = "BearerB64Rule"
        subbytesb64 = ["QmVhcmVyIA=="] # "Bearer "
        level = 2

        [[bytes_obfuscation.rules]]
        name = "ExcludeDummyKey"
        subbytesarr = [0x73, 0x6b, 0x2d, 0x6c, 0x69, 0x76, 0x65, 0x2d, 0x30, 0x30] # "sk-live-00"
        exclude = true
    "#;

    let (ir, logs) = common::run_opt("bytes.ll", "bo,verify", toml);

    assert!(
        logs.contains("发现 4 个待混淆字节串"),
        "候选常量数量不匹配，日志:\n{logs}"
    );
    assert!(
        logs.contains("字节串混淆完成：成功替换 6 处指令引用，彻底抹除 3 个明文全局常量。"),
        "替换统计不匹配，日志:\n{logs}"
    );

    assert!(!ir.contains("sk-live-0123456789abcdef1234"));
    assert!(!ir.contains("Bearer phi-branch-alpha!"));
    assert!(!ir.contains("Bearer phi-branch-bravo!"));
    assert!(!ir.contains("@secret_key ="));
    assert!(!ir.contains("@phi_secret_a ="));
    assert!(!ir.contains("@phi_secret_b ="));

    assert!(ir.contains("@shared_secret ="));
    assert!(!ir.contains("ret ptr @shared_secret"));

    assert!(ir.contains("sk-live-0023456789abcdef1234"));
    assert!(ir.contains("ret ptr @excluded_key"));
    assert!(ir.contains("sk-live-mutable-0123456789ab"));
    assert!(
        ir.contains(r#"@safe_str = private unnamed_addr constant [12 x i8] c"hello world\00""#)
    );
}

#[test]
fn test_bo_opt_other_pct_full_sampling() {
    let toml = r#"
        [rust_toolchain]
        toolchain = "nightly-2026-04-02"

        [bytes_obfuscation]
        enabled = true
        other_pct = 100
        other_level = 1
    "#;

    let (ir, logs) = common::run_opt("bytes.ll", "bo,verify", toml);

    assert!(
        logs.contains("发现 6 个待混淆字节串"),
        "全量抽样候选数量不匹配，日志:\n{logs}"
    );
    assert!(
        logs.contains("字节串混淆完成：成功替换 8 处指令引用，彻底抹除 5 个明文全局常量。"),
        "全量抽样替换统计不匹配，日志:\n{logs}"
    );
    assert!(!ir.contains("hello world"));
    assert!(!ir.contains("sk-live-0023456789abcdef1234"));
    assert!(ir.contains("sk-live-mutable-0123456789ab"));
}

#[test]
fn test_bo_opt_disabled() {
    let toml = r#"
        [bytes_obfuscation]
        enabled = false
        other_pct = 100
    "#;

    let (ir, logs) = common::run_opt("bytes.ll", "bo,verify", toml);
    assert!(logs.contains("Pass 已在配置中禁用，跳过。"));
    assert!(ir.contains("sk-live-0123456789abcdef1234"));
    assert!(ir.contains("Bearer phi-branch-alpha!"));
}

#[test]
fn test_bo_cargo_project_e2e() {
    let toml = r#"
        [rust_toolchain]
        toolchain = "nightly-2026-04-02"
        allocator = "talc"

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
    "#;

    let bin_path = common::build_demo_atest("bo", "bo", Some(toml));

    let status = Command::new(&bin_path)
        .args(["--check-bo", "--check-flow"])
        .status()
        .expect("Failed to run atest --check-bo --check-flow");
    assert!(status.success(), "atest --check-bo --check-flow failed");

    let bin_bytes = fs::read(&bin_path).expect("read compiled binary");
    let bin_lossy = String::from_utf8_lossy(&bin_bytes);
    assert!(
        !bin_lossy.contains("sk-live-bo-e2e-0123456789abcdef"),
        "明文敏感字节串不应存在于编译后的二进制文件中"
    );
    assert!(
        !bin_lossy.contains("Bearer sk-live-bo-e2e-"),
        "明文前缀与特征子串不应存在于编译后的二进制文件中"
    );
}

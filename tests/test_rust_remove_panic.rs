// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// tests/test_rust_remove_panic.rs
mod common;

use std::process::Command;

#[test]
fn test_rp_opt_trap_mode_and_dce() {
    let toml = r#"
        [rust_remove_panic]
        enabled = true
        mode = "trap"
    "#;

    let (ir, logs) = common::run_opt("panic.ll", "rp,verify", toml);

    assert!(logs.contains("发现 2 个 rust panic 相关函数 (mode: Trap)"));
    assert!(ir.contains("call void @llvm.trap()"));
    assert!(
        ir.contains(r#"[ "deopt"(i32"#),
        "Operand bundle must be preserved"
    );
    assert!(
        !ir.contains("define internal void @_ZN4core9panicking18panic_bounds_check"),
        "Gutted panic function should be removed by GlobalDCE"
    );
}

#[test]
fn test_rp_opt_exit_mode_custom_code() {
    let toml = r#"
        [rust_remove_panic]
        enabled = true
        mode = "exit"
        exit_code = 233
    "#;

    let (ir, logs) = common::run_opt("panic.ll", "rp,verify", toml);

    assert!(logs.contains("发现 2 个 rust panic 相关函数 (mode: Exit)"));
    assert!(ir.contains("call void @exit(i32 233)"));
}

#[test]
fn test_rp_cargo_project_e2e() {
    // 仅挂载 `rp` Pass 编译 demo/atest
    let bin_path = common::build_demo_atest("rp", "rp", None);

    // 1. 验证正常同步与 Tokio 异步状态机未被破坏
    let flow_status = Command::new(&bin_path)
        .arg("--check-flow")
        .status()
        .expect("Failed to run atest --check-flow");
    assert!(
        flow_status.success(),
        "Normal control flow failed under rp pass"
    );

    // 2. 触发数组越界 Panic，验证进程异常终止且无任何 Panic 格式化文本输出
    let panic_out = Command::new(&bin_path)
        .arg("--trigger-panic")
        .output()
        .expect("Failed to run atest --trigger-panic");

    assert!(
        !panic_out.status.success(),
        "Process should terminate abnormally on bounds check panic"
    );
    let stderr = String::from_utf8_lossy(&panic_out.stderr);
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("index out of bounds"),
        "Panic formatting message should be completely stripped, got:\n{stderr}"
    );
}

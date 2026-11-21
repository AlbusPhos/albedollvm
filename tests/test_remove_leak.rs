// tests/test_remove_leak.rs
mod common;

use std::fs;
use std::process::Command;

#[test]
fn test_rl_opt_scrubs_builtins_and_custom_rules() {
    let toml = r#"
        [remove_leak]
        enabled = true
        enable_builtins = true

        [[remove_leak.rules]]
        name = "InternalSecretKey"
        min_len = 16
        max_len = 256
        substrings = ["sk-live-", "sk-test-"]
        regex = '(sk-(?:live|test)-[0-9a-zA-Z]{16,64})'
    "#;

    let (ir, logs) = common::run_opt("leak.ll", "rl,verify", toml);

    assert!(logs.contains("已清理 3 个敏感字符串常量。"));
    assert!(!ir.contains("/rustc/3659db0d3e2cd634c766fcda79ed118eca31a3fd"));
    assert!(!ir.contains("src/utils/helper.rs"));
    assert!(!ir.contains("sk-live-0123456789abcdef"));

    assert!(ir.contains("@rustc_path = private unnamed_addr constant [74 x i8]"));
    assert!(ir.contains("@src_path = private unnamed_addr constant [19 x i8]"));
    assert!(ir.contains(r#"@safe_str = private unnamed_addr constant [12 x i8] c"hello world\00""#));
}

#[test]
fn test_rl_opt_disabled() {
    let toml = r#"
        [remove_leak]
        enabled = false
    "#;

    let (ir, logs) = common::run_opt("leak.ll", "rl,verify", toml);
    assert!(logs.contains("Pass 已在配置中禁用，跳过。"));
    assert!(ir.contains("sk-live-0123456789abcdef"));
}

#[test]
fn test_rl_cargo_project_e2e() {
    let bin_path = common::build_demo_atest("rl", "rl", None);

    let status = Command::new(&bin_path)
        .args(["--check-leak", "--check-flow"])
        .status()
        .expect("Failed to run atest");
    assert!(status.success(), "atest --check-leak --check-flow failed");

    let bin_bytes = fs::read(&bin_path).expect("read compiled binary");
    let bin_lossy = String::from_utf8_lossy(&bin_bytes);
    assert!(!bin_lossy.contains("sk-live-0123456789"));
    assert!(!bin_lossy.contains("/rustc/"));
    assert!(!bin_lossy.contains("src/main.rs"));
}
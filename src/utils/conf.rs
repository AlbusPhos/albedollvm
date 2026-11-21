// src/utils/conf.rs
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::Deserialize;

use crate::*;

const TAG: &str = "OLLVM_CONFIG";
const CONFIG_PATH_ENV: &str = "OLLVM_CONFIG";
const DEFAULT_CONFIG_FILE: &str = "ollvm.toml";

/// 全局唯一配置实例，整个编译期仅读取、合并和解析一次
pub static CONFIG: LazyLock<OllvmConfig> = LazyLock::new(OllvmConfig::load);

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct OllvmConfig {
    pub rust_remove_panic: RustRemovePanicConfig,
    pub remove_leak: RemoveLeakConfig,
}

impl OllvmConfig {
    fn load() -> Self {
        let mut cfg = Self::load_raw();
        cfg.remove_leak.finalize();
        cfg
    }

    fn load_raw() -> Self {
        let (path, is_explicit) = Self::resolve_path();

        if !path.exists() {
            if is_explicit {
                pwarn!(
                    TAG,
                    "环境变量 {} 指定的配置文件不存在: {}，将使用默认配置。",
                    CONFIG_PATH_ENV,
                    path.display()
                );
            } else {
                pdebug!(TAG, "未检测到 {}，使用内置默认配置。", path.display());
            }
            return Self::default();
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                pwarn!(
                    TAG,
                    "无法读取配置文件 {}: {}，将使用默认配置。",
                    path.display(),
                    err
                );
                return Self::default();
            }
        };

        match toml::from_str::<Self>(&content) {
            Ok(cfg) => {
                pinfo!(TAG, "已加载配置文件: {}", path.display());
                cfg
            }
            Err(err) => {
                pwarn!(
                    TAG,
                    "配置文件 {} 解析失败: {}，将使用默认配置。",
                    path.display(),
                    err
                );
                Self::default()
            }
        }
    }

    /// 返回 (配置文件路径, 是否由环境变量显式指定)
    fn resolve_path() -> (PathBuf, bool) {
        if let Some(env_path) = env::var_os(CONFIG_PATH_ENV)
            && !env_path.is_empty()
        {
            return (PathBuf::from(env_path), true);
        }
        (Path::new(DEFAULT_CONFIG_FILE).to_path_buf(), false)
    }
}

/// Panic 替换模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PanicMode {
    /// 调用 C 标准库 `void @exit(i32)`
    #[default]
    Exit,
    /// 调用 LLVM 内建函数 `void @llvm.trap()`（x86 下为 `ud2`，ARM64 下为 `brk`）
    Trap,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RustRemovePanicConfig {
    pub enabled: bool,
    pub mode: PanicMode,
    pub exit_code: i32,
}

impl Default for RustRemovePanicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: PanicMode::Exit,
            exit_code: 101,
        }
    }
}


#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RemoveLeakConfig {
    /// 是否启用 RemoveLeak Pass
    pub enabled: bool,
    /// 是否启用内置规则 (HomeDir, RustcLibrary, SrcPath)
    pub enable_builtins: bool,
    /// 最终生效的规则列表（finalize 后包含：内置规则 + TOML 自定义规则）
    pub rules: Vec<LeakRuleConfig>,
}

impl Default for RemoveLeakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_builtins: true,
            rules: Vec::new(),
        }
    }
}

impl RemoveLeakConfig {
    /// 将内置规则与用户在 TOML 中配置的自定义规则合并（若用户定义了同名规则，则以用户规则为准）
    fn finalize(&mut self) {
        if !self.enabled || !self.enable_builtins {
            return;
        }

        let custom_rules = std::mem::take(&mut self.rules);
        let mut merged = Self::builtin_rules();
        merged.reserve(custom_rules.len());

        // 如果用户在 TOML 中定义了与内置规则同名的规则，允许覆盖内置规则
        merged.retain(|builtin| !custom_rules.iter().any(|c| c.name == builtin.name));
        merged.extend(custom_rules);

        self.rules = merged;
    }

    /// 内置默认规则集
    pub fn builtin_rules() -> Vec<LeakRuleConfig> {
        const BUILTIN_LEAK_MAX_LEN: usize = 1024;

        let mut builtins = Vec::with_capacity(3);

        // HomeDir: /home/zwls/Documents/Project/Rust/code-auth/sdk
        if let Some(home_dir) = user_home_dir() {
            let regex = format!("({}[a-zA-Z0-9_./\\-]{{0,250}})", regex::escape(&home_dir));
            let min_len = home_dir.len();
            builtins.push(LeakRuleConfig {
                name: "HomeDir".to_owned(),
                min_len,
                max_len: Some(BUILTIN_LEAK_MAX_LEN),
                substrings: vec![home_dir],
                regex,
            });
        } else {
            pwarn!(TAG, "无法获取有效用户主目录，跳过内置 HomeDir 规则。");
        }

        // RustcLibrary: /rustc/3659db0d3e2cd634c766fcda79ed118eca31a3fd/library/std/src/...
        builtins.push(LeakRuleConfig {
            name: "RustcLibrary".to_owned(),
            min_len: 56, // "/rustc/" (7) + 40位hash (40) + "/library/" (9)
            max_len: Some(BUILTIN_LEAK_MAX_LEN),
            substrings: vec!["/rustc/".to_owned()],
            regex: r"(/rustc/[0-9a-f]{40}/library/[a-zA-Z0-9_./\-]{0,200})".to_owned(),
        });

        // SrcPath: src/main.rs, src/lib.rs, src/utils/helper.rs
        builtins.push(LeakRuleConfig {
            name: "SrcPath".to_owned(),
            min_len: 7, // "src/.rs"
            max_len: Some(BUILTIN_LEAK_MAX_LEN),
            substrings: vec!["src/".to_owned(), r"src\".to_owned()],
            regex: r"(src[/\\][a-zA-Z0-9_./\\\-]{0,200}\.rs)".to_owned(),
        });
        // RustPanicAndBacktrace: 清理 std/core 残留的 panic、assert 与 backtrace 提示信息
        builtins.push(LeakRuleConfig {
            name: "RustPanicAndBacktrace".to_owned(),
            min_len: 11,
            max_len: None,
            substrings: vec![
                "panicked at".to_owned(),
                "RUST_BACKTRACE".to_owned(),
                "RUST_MIN_STACK".to_owned(),
                "stack backtrace".to_owned(),
                "_short_backtrace".to_owned(),
                "fatal runtime error:".to_owned(),
                "entered unreachable code".to_owned(),
                "assertion failed:".to_owned(),
                "::unwrap()` on a".to_owned(),
                "punycode{".to_owned(),
                ".llvm.".to_owned(),
            ],
            regex: r"(panicked at|RUST_BACKTRACE(?:=1|=full)?|RUST_MIN_STACK|stack backtrace:|__rust_(?:begin|end)_short_backtrace|fatal runtime error:[a-zA-Z0-9_ ,:()'`.!\-]{0,120}|internal error: entered unreachable code[a-zA-Z0-9_ ,:()'`.!\-]{0,80}|assertion failed:[a-zA-Z0-9_ ,:()'`.!=<>+\-&|]{0,100}|called `(?:Option|Result)::unwrap\(\)` on an? `(?:None|Err)` value|punycode\{\}|\.llvm\.)".to_owned(),
        });
        // TokioRuntimeFingerprint: 隐藏 Tokio 工作线程名称、环境变量与内部错误提示
        builtins.push(LeakRuleConfig {
            name: "TokioRuntimeFingerprint".to_owned(),
            min_len: 10,
            max_len: None,
            substrings: vec![
                "tokio-".to_owned(),
                "TOKIO_".to_owned(),
                "Tokio ".to_owned(),
            ],
            regex: r"(tokio-rt-worker|TOKIO_[A-Z_]{6,40}|[a-zA-Z0-9 ,.`'()!:\-]{0,60}Tokio [a-zA-Z0-9 ,.`'()!:\-]{0,80})".to_owned(),
        });

        builtins
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeakRuleConfig {
    /// 规则名称（用于日志追踪，若与内置规则同名可覆盖内置规则）
    pub name: String,
    /// 目标字符串的最小字节长度（默认 1）
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    /// 目标字符串的最大字节长度（不填则默认无上限 usize::MAX）
    #[serde(default)]
    pub max_len: Option<usize>,
    /// 预筛子串列表：非空时，目标字符串必须包含其中【至少一个】子串才进入正则匹配
    #[serde(default)]
    pub substrings: Vec<String>,
    /// 完整正则表达式
    pub regex: String,
}

const fn default_min_len() -> usize {
    1
}

fn user_home_dir() -> Option<String> {
    let value = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"))?;
    let home = value.to_string_lossy();
    if home.len() <= 1 {
        return None;
    }
    Some(home.into_owned())
}

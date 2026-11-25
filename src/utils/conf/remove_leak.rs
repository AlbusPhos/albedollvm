// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// src/utils/conf/remove_leak.rs

use std::env;

use memchr::memmem::Finder;
use regex::bytes::{Match as BytesMatch, Regex as BytesRegex};
use serde::Deserialize;

use super::TAG;
use crate::pwarn;

const fn default_min_len() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RemoveLeakConfig {
    /// 是否启用 RemoveLeak Pass
    pub enabled: bool,
    /// 是否启用内置规则 (HomeDir, RustcLibrary, SrcPath, RustPanicAndBacktrace, TokioRuntimeFingerprint)
    pub enable_builtins: bool,
    /// 最终生效的规则列表（finalize 后包含：内置规则 + TOML 自定义规则）
    #[serde(alias = "rule")]
    pub rules: Vec<LeakRuleConfig>,

    /// finalize 阶段计算的全局最小匹配长度（用于 Level 0 快筛）
    #[serde(skip)]
    global_min_len: usize,
    /// finalize 阶段计算的全局最大匹配长度（用于 Level 0 快筛）
    #[serde(skip)]
    global_max_len: usize,
}

impl Default for RemoveLeakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_builtins: true,
            rules: Vec::new(),
            global_min_len: usize::MAX,
            global_max_len: 0,
        }
    }
}

impl RemoveLeakConfig {
    pub(super) fn finalize(&mut self) {
        if !self.enabled {
            self.global_min_len = usize::MAX;
            self.global_max_len = 0;
            return;
        }

        if self.enable_builtins {
            let custom_rules = std::mem::take(&mut self.rules);
            let mut merged = Self::builtin_rules();
            merged.reserve(custom_rules.len());

            // 如果用户在 TOML 中定义了与内置规则同名的规则，允许覆盖内置规则
            merged.retain(|builtin| !custom_rules.iter().any(|c| c.name == builtin.name));
            merged.extend(custom_rules);

            self.rules = merged;
        }

        let mut idx = 0usize;
        self.rules.retain_mut(|rule| {
            let current_idx = idx;
            idx += 1;
            if rule.name.trim().is_empty() {
                rule.name = format!("unnamed_{current_idx}");
            }
            rule.finalize_rule()
        });

        self.global_min_len = self
            .rules
            .iter()
            .map(|r| r.min_len)
            .min()
            .unwrap_or(usize::MAX);
        self.global_max_len = self
            .rules
            .iter()
            .map(|r| r.max_len.unwrap_or(usize::MAX))
            .max()
            .unwrap_or(0);
    }

    /// Level 0 全局长度快筛：判断候选字节串是否落在任一规则的长度区间内
    #[inline]
    pub fn might_match_any(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        len >= self.global_min_len && len <= self.global_max_len
    }

    /// 内置默认规则集
    pub fn builtin_rules() -> Vec<LeakRuleConfig> {
        const BUILTIN_LEAK_MAX_LEN: usize = 1024;

        let mut builtins = Vec::with_capacity(5);

        // HomeDir: /home/zwls/Documents/Project/Rust/code-auth/sdk
        if let Some(home_dir) = user_home_dir() {
            let regex = format!("({}[a-zA-Z0-9_./\\-]{{0,250}})", regex::escape(&home_dir));
            let min_len = home_dir.len();
            builtins.push(LeakRuleConfig::new(
                "HomeDir",
                min_len,
                Some(BUILTIN_LEAK_MAX_LEN),
                vec![home_dir],
                regex,
            ));
        } else {
            pwarn!(TAG, "无法获取有效用户主目录，跳过内置 HomeDir 规则。");
        }

        // RustcLibrary: /rustc/3659db0d3e2cd634c766fcda79ed118eca31a3fd/library/std/src/...
        builtins.push(LeakRuleConfig::new(
            "RustcLibrary",
            56, // "/rustc/" (7) + 40位hash (40) + "/library/" (9)
            Some(BUILTIN_LEAK_MAX_LEN),
            vec!["/rustc/".to_owned()],
            r"(/rustc/[0-9a-f]{40}/library/[a-zA-Z0-9_./\-]{0,200})",
        ));

        // SrcPath: src/main.rs, src/lib.rs, src/utils/helper.rs
        builtins.push(LeakRuleConfig::new(
            "SrcPath",
            7, // "src/.rs"
            Some(BUILTIN_LEAK_MAX_LEN),
            vec!["src/".to_owned(), r"src\".to_owned()],
            r"(src[/\\][a-zA-Z0-9_./\\\-]{0,200}\.rs)",
        ));

        // RustPanicAndBacktrace: 清理 std/core 残留的 panic、assert 与 backtrace 提示信息
        builtins.push(LeakRuleConfig::new(
            "RustPanicAndBacktrace",
            11,
            None,
            vec![
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
            r"(panicked at|RUST_BACKTRACE(?:=1|=full)?|RUST_MIN_STACK|stack backtrace:|__rust_(?:begin|end)_short_backtrace|fatal runtime error:[a-zA-Z0-9_ ,:()'`.!\-]{0,120}|internal error: entered unreachable code[a-zA-Z0-9_ ,:()'`.!\-]{0,80}|assertion failed:[a-zA-Z0-9_ ,:()'`.!=<>+\-&|]{0,100}|called `(?:Option|Result)::unwrap\(\)` on an? `(?:None|Err)` value|punycode\{\}|\.llvm\.)",
        ));

        // TokioRuntimeFingerprint: 隐藏 Tokio 工作线程名称、环境变量与内部错误提示
        builtins.push(LeakRuleConfig::new(
            "TokioRuntimeFingerprint",
            10,
            None,
            vec![
                "tokio-".to_owned(),
                "TOKIO_".to_owned(),
                "Tokio ".to_owned(),
            ],
            r"(tokio-rt-worker|TOKIO_[A-Z_]{6,40}|[a-zA-Z0-9 ,.`'()!:\-]{0,60}Tokio [a-zA-Z0-9 ,.`'()!:\-]{0,80})",
        ));

        builtins
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeakRuleConfig {
    /// 规则名称（用于日志追踪，若与内置规则同名可覆盖内置规则）
    #[serde(default)]
    pub name: String,
    /// 目标字符串的最小字节长度（默认 1）
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    /// 目标字符串的最大字节长度（不填则默认无上限）
    #[serde(default)]
    pub max_len: Option<usize>,
    /// 预筛子串列表：非空时，目标字符串必须包含其中【至少一个】子串才进入正则匹配
    #[serde(default)]
    pub substrings: Vec<String>,
    /// 完整正则表达式
    #[serde(default)]
    pub regex: String,

    /// finalize 阶段预构建的 SIMD 字节子串搜索器集合
    #[serde(skip)]
    compiled_substrings: Vec<Finder<'static>>,
    /// finalize 阶段预编译的字节正则表达式
    #[serde(skip)]
    compiled_regex: Option<BytesRegex>,
}

impl LeakRuleConfig {
    pub fn new(
        name: impl Into<String>,
        min_len: usize,
        max_len: Option<usize>,
        substrings: Vec<String>,
        regex: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            min_len,
            max_len,
            substrings,
            regex: regex.into(),
            compiled_substrings: Vec::new(),
            compiled_regex: None,
        }
    }

    fn finalize_rule(&mut self) -> bool {
        // 1. 校验长度区间
        if self.min_len == 0 {
            self.min_len = 1;
        }
        if let Some(max_len) = self.max_len
            && max_len < self.min_len
        {
            pwarn!(
                TAG,
                "[[remove_leak.rules]] 规则 '{}' 的 max_len ({}) < min_len ({})，已跳过。",
                self.name,
                max_len,
                self.min_len
            );
            return false;
        }

        // 2. 预构建 SIMD 子串搜索器 (memchr::memmem::Finder)
        self.compiled_substrings.clear();
        for s in &self.substrings {
            if !s.is_empty() {
                self.compiled_substrings
                    .push(Finder::new(s.as_bytes()).into_owned());
            }
        }

        // 利用最短预筛子串长度自动收紧 min_len 下界
        if let Some(shortest_sub) = self
            .compiled_substrings
            .iter()
            .map(|f| f.needle().len())
            .min()
        {
            if let Some(max_len) = self.max_len
                && shortest_sub > max_len
            {
                pwarn!(
                    TAG,
                    "[[remove_leak.rules]] 规则 '{}' 的预筛子串最短长度 ({}) 超过 max_len ({})，永远无法命中，已跳过。",
                    self.name,
                    shortest_sub,
                    max_len
                );
                return false;
            }
            self.min_len = self.min_len.max(shortest_sub);
        }

        // 3. 预编译字节正则表达式
        if self.regex.is_empty() {
            pwarn!(
                TAG,
                "[[remove_leak.rules]] 规则 '{}' 的 regex 为空，已跳过。",
                self.name
            );
            return false;
        }

        match BytesRegex::new(&self.regex) {
            Ok(re) => {
                self.compiled_regex = Some(re);
                true
            }
            Err(err) => {
                pwarn!(
                    TAG,
                    "[[remove_leak.rules]] 规则 '{}' 正则编译失败，已跳过: {} (错误: {})",
                    self.name,
                    self.regex,
                    err
                );
                false
            }
        }
    }

    /// 规则长度区间校验 + SIMD 字节子串预筛
    #[inline]
    pub fn might_match(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        if len < self.min_len || self.max_len.is_some_and(|max| len > max) {
            return false;
        }
        if self.compiled_substrings.is_empty() {
            return true;
        }
        self.compiled_substrings
            .iter()
            .any(|finder| finder.find(bytes).is_some())
    }

    /// 从 `start` 偏移处开始搜索下一个正则匹配项
    #[inline]
    pub fn find_at<'a>(&self, bytes: &'a [u8], start: usize) -> Option<BytesMatch<'a>> {
        self.compiled_regex.as_ref()?.find_at(bytes, start)
    }
}

fn user_home_dir() -> Option<String> {
    let value = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"))?;
    let home = value.to_string_lossy();
    if home.len() <= 1 {
        return None;
    }
    Some(home.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finalize_and_matching() {
        let toml_str = r#"
            enabled = true
            enable_builtins = true

            [[rules]]
            name = "CustomBuildHost"
            substrings = ["builder@corp.internal"]
            regex = 'builder@corp\.internal:[a-zA-Z0-9_/\-]+'
        "#;

        let mut cfg: RemoveLeakConfig = toml::from_str(toml_str).unwrap();
        cfg.finalize();

        let custom_rule = cfg
            .rules
            .iter()
            .find(|r| r.name == "CustomBuildHost")
            .unwrap();
        assert_eq!(custom_rule.min_len, "builder@corp.internal".len());

        let sample = b"Error at src/utils/conf.rs:42 built by builder@corp.internal:/work/repo";
        assert!(cfg.might_match_any(sample));
        assert!(custom_rule.might_match(sample));
        let m = custom_rule.find_at(sample, 0).unwrap();
        assert_eq!(
            &sample[m.start()..m.end()],
            b"builder@corp.internal:/work/repo"
        );
    }
}

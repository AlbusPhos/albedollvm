// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// src/utils/conf/bytes_obfuscation.rs
use super::TAG;
use crate::{pdebug, pwarn};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use lib_unknown::rand::core::random_range;
use memchr::memmem::Finder;
use regex::bytes::Regex as BytesRegex;
use serde::Deserialize;

const MIN_OBF_LEVEL: u8 = 1;
const MAX_OBF_LEVEL: u8 = 3;
/// 默认单函数栈解密空间预算：4 KiB
pub const DEFAULT_STACK_BUDGET: usize = 4096;
/// 单函数栈解密空间预算安全上限：64 KiB（防止栈帧过度膨胀导致 Stack Overflow）
pub const MAX_STACK_BUDGET: usize = 64 * 1024;

const fn default_enabled() -> bool {
    true
}
const fn default_stack_budget() -> usize {
    DEFAULT_STACK_BUDGET
}
const fn default_min_len() -> usize {
    1
}
const fn default_level() -> u8 {
    1
}

/// `[bytes_obfuscation]` 顶层配置
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BytesObfuscationConfig {
    /// 是否启用 BytesObfuscation Pass（默认 true）
    pub enabled: bool,
    /// 单函数非 Lazy 栈解密的最大字节预算（默认 4096；设为 0 则禁用栈解密，全部使用 Lazy 静态堆模式）
    pub stack_budget: usize,
    /// 对未命中任何规则的其他字节串，按该百分比概率 (0..=100) 启用混淆
    pub other_pct: u8,
    /// `other_pct` 抽样命中时使用的 obfstr2 混淆等级 (1..=3)
    pub other_level: u8,
    /// 显式字节串匹配规则列表：`[[bytes_obfuscation.rule]]`
    #[serde(alias = "rule")]
    pub rules: Vec<BytesRuleConfig>,
}

impl Default for BytesObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            stack_budget: default_stack_budget(),
            other_pct: 0,
            other_level: default_level(),
            rules: Vec::new(),
        }
    }
}

/// 单条字节串匹配规则：`[[bytes_obfuscation.rules]]`
#[derive(Debug, Clone, Deserialize)]
pub struct BytesRuleConfig {
    /// 规则名称（用于日志追踪）
    #[serde(default)]
    pub name: String,
    /// 目标字节串的最小长度（默认 1）
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    /// 目标字节串的最大长度（不填则无上限）
    #[serde(default)]
    pub max_len: Option<usize>,
    /// 预筛方式 1：UTF-8 子串列表
    #[serde(default)]
    pub substrings: Vec<String>,
    /// 预筛方式 2：Base64 编码的字节子串列表
    #[serde(default)]
    pub subbytesb64: Vec<String>,
    /// 预筛方式 3：单组原始字节数组（如 `[0x73, 0x6b, 0x2d]`）
    #[serde(default)]
    pub subbytesarr: Vec<u8>,
    /// 可选：完整字节正则表达式（`regex::bytes::Regex`）
    #[serde(default)]
    pub regex: Option<String>,
    /// 控制是排除 (`true`) 还是启用 (`false`，默认)
    #[serde(default)]
    pub exclude: bool,
    /// 命中该规则时使用的 obfstr2 混淆等级 (1..=3，默认 1)
    #[serde(default = "default_level")]
    pub level: u8,
    /// finalize 阶段预构建的 SIMD 子串搜索器集合（非空）
    #[serde(skip)]
    compiled_subbytes: Vec<Finder<'static>>,
    /// finalize 阶段预编译的字节正则表达式
    #[serde(skip)]
    compiled_regex: Option<BytesRegex>,
}

impl BytesObfuscationConfig {
    pub(super) fn finalize(&mut self) {
        if !self.enabled {
            return;
        }
        if self.stack_budget > MAX_STACK_BUDGET {
            pwarn!(
                TAG,
                "[bytes_obfuscation] stack_budget = {} 超出安全上限 {} (64 KiB)，已截断为 {}。",
                self.stack_budget,
                MAX_STACK_BUDGET,
                MAX_STACK_BUDGET
            );
            self.stack_budget = MAX_STACK_BUDGET;
        }
        if self.other_pct > 100 {
            pwarn!(
                TAG,
                "[bytes_obfuscation] other_pct = {} 超出 0..=100 范围，已截断为 100。",
                self.other_pct
            );
            self.other_pct = 100;
        }
        self.other_level = clamp_level("[bytes_obfuscation] other_level", self.other_level);
        let mut idx = 0usize;
        self.rules.retain_mut(|rule| {
            let current_idx = idx;
            idx += 1;
            if rule.name.trim().is_empty() {
                rule.name = format!("unnamed_{current_idx}");
            }
            rule.finalize_rule()
        });
    }

    /// 核心决策入口：给定 LLVM IR 中的候选字节串 `data`，
    /// 返回 `Some(level)`（1..=3）表示应使用对应档位的 `obfstr2` 混淆，`None` 表示跳过。
    pub fn decide(&self, data: &[u8]) -> Option<u8> {
        if !self.enabled || data.is_empty() {
            return None;
        }
        let mut matched_include: Option<(usize, &BytesRuleConfig)> = None;
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.exclude {
                if rule.matches(data) {
                    pdebug!(
                        TAG,
                        "[bytes_obfuscation] 字节串 (len={}) 命中排除规则 #{} ({})，跳过。",
                        data.len(),
                        idx,
                        rule.name
                    );
                    return None;
                }
            } else if matched_include.is_none() && rule.matches(data) {
                matched_include = Some((idx, rule));
            }
        }
        if let Some((idx, rule)) = matched_include {
            pdebug!(
                TAG,
                "[bytes_obfuscation] 字节串 (len={}) 命中启用规则 #{} ({})，level = {}。",
                data.len(),
                idx,
                rule.name,
                rule.level
            );
            return Some(rule.level);
        }
        if self.other_pct == 0 {
            return None;
        }
        if random_range(1..=100u8) <= self.other_pct {
            pdebug!(
                TAG,
                "[bytes_obfuscation] 字节串 (len={}) 命中 other_pct ({}%) 概率抽样，level = {}。",
                data.len(),
                self.other_pct,
                self.other_level
            );
            Some(self.other_level)
        } else {
            None
        }
    }
}

impl BytesRuleConfig {
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
                "[[bytes_obfuscation.rules]] 规则 '{}' 的 max_len ({}) < min_len ({})，已忽略。",
                self.name,
                max_len,
                self.min_len
            );
            return false;
        }
        // 2. 校验混淆等级 (1..=3)
        self.level = clamp_level(&format!("规则 '{}' level", self.name), self.level);
        // 3. 严格校验 substrings / subbytesb64 / subbytesarr 互斥约束（必须有且仅有一个启用）
        let has_substrings = !self.substrings.is_empty();
        let has_b64 = !self.subbytesb64.is_empty();
        let has_arr = !self.subbytesarr.is_empty();
        let active_count = u8::from(has_substrings) + u8::from(has_b64) + u8::from(has_arr);
        if active_count != 1 {
            pwarn!(
                TAG,
                "[[bytes_obfuscation.rules]] 规则 '{}' 必须有且仅有 substrings / subbytesb64 / subbytesarr 之一启用（当前启用数: {}），已忽略。",
                self.name,
                active_count
            );
            return false;
        }
        // 4. 归一化预筛子串至 compiled_subbytes（预构建 memchr::memmem::Finder）
        self.compiled_subbytes.clear();
        if has_substrings {
            for s in &self.substrings {
                if !s.is_empty() {
                    self.compiled_subbytes
                        .push(Finder::new(s.as_bytes()).into_owned());
                }
            }
        } else if has_b64 {
            for b64 in &self.subbytesb64 {
                let trimmed = b64.trim();
                let decoded = STANDARD
                    .decode(trimmed)
                    .or_else(|_| STANDARD_NO_PAD.decode(trimmed));
                match decoded {
                    Ok(bytes) if !bytes.is_empty() => {
                        self.compiled_subbytes
                            .push(Finder::new(&bytes).into_owned());
                    }
                    Ok(_) => {
                        pwarn!(
                            TAG,
                            "[[bytes_obfuscation.rules]] 规则 '{}' 含有解码后为空的 subbytesb64 项，已忽略该规则。",
                            self.name
                        );
                        return false;
                    }
                    Err(err) => {
                        pwarn!(
                            TAG,
                            "[[bytes_obfuscation.rules]] 规则 '{}' 的 subbytesb64 ('{}') 解码失败 ({})，已忽略该规则。",
                            self.name,
                            b64,
                            err
                        );
                        return false;
                    }
                }
            }
        } else if has_arr {
            self.compiled_subbytes
                .push(Finder::new(&self.subbytesarr).into_owned());
        }
        if self.compiled_subbytes.is_empty() {
            pwarn!(
                TAG,
                "[[bytes_obfuscation.rules]] 规则 '{}' 的有效预筛子串为空，已忽略。",
                self.name
            );
            return false;
        }
        // 利用最短预筛子串长度自动收紧 min_len 下界
        if let Some(shortest_sub) = self
            .compiled_subbytes
            .iter()
            .map(|f| f.needle().len())
            .min()
        {
            if let Some(max_len) = self.max_len
                && shortest_sub > max_len
            {
                pwarn!(
                    TAG,
                    "[[bytes_obfuscation.rules]] 规则 '{}' 的预筛子串最短长度 ({}) 超过 max_len ({})，永远无法命中，已忽略。",
                    self.name,
                    shortest_sub,
                    max_len
                );
                return false;
            }
            self.min_len = self.min_len.max(shortest_sub);
        }
        // 5. 预编译可选的 bytes::Regex
        if let Some(pattern) = &self.regex {
            if pattern.is_empty() {
                self.compiled_regex = None;
            } else {
                match BytesRegex::new(pattern) {
                    Ok(re) => self.compiled_regex = Some(re),
                    Err(err) => {
                        pwarn!(
                            TAG,
                            "[[bytes_obfuscation.rules]] 规则 '{}' 的正则 '{}' 编译失败: {}，已忽略。",
                            self.name,
                            pattern,
                            err
                        );
                        return false;
                    }
                }
            }
        }
        true
    }

    /// 三级漏斗匹配：长度预筛 -> SIMD 字节子串预筛 -> 正则精筛
    #[inline]
    pub fn matches(&self, data: &[u8]) -> bool {
        let len = data.len();
        if len < self.min_len || self.max_len.is_some_and(|max| len > max) {
            return false;
        }
        if !self
            .compiled_subbytes
            .iter()
            .any(|finder| finder.find(data).is_some())
        {
            return false;
        }
        if let Some(re) = &self.compiled_regex {
            return re.is_match(data);
        }
        true
    }
}

#[inline]
fn clamp_level(context: &str, level: u8) -> u8 {
    if !(MIN_OBF_LEVEL..=MAX_OBF_LEVEL).contains(&level) {
        let clamped = level.clamp(MIN_OBF_LEVEL, MAX_OBF_LEVEL);
        pwarn!(
            TAG,
            "[bytes_obfuscation] {} = {} 超出 {}..={} 范围，已调整为 {}。",
            context,
            level,
            MIN_OBF_LEVEL,
            MAX_OBF_LEVEL,
            clamped
        );
        clamped
    } else {
        level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_decide_bytes_obfuscation() {
        let toml_str = r#"
            stack_budget = 8192
            other_pct = 0
            other_level = 1
            [[rules]]
            name = "InternalSecretKey"
            min_len = 24
            max_len = 256
            substrings = ["sk-live-", "sk-test-"]
            regex = 'sk-(?:live|test)-[0-9a-zA-Z]{16,64}'
            exclude = false
            level = 3
            [[rules]]
            name = "Base64Rule"
            subbytesb64 = ["c2stbGl2ZS0="] # "sk-live-"
            level = 2
            [[rules]]
            name = "ExcludeDummyKey"
            subbytesarr = [0x73, 0x6b, 0x2d, 0x6c, 0x69, 0x76, 0x65, 0x2d, 0x30, 0x30] # "sk-live-00"
            exclude = true
        "#;
        let mut cfg: BytesObfuscationConfig = toml::from_str(toml_str).unwrap();
        cfg.finalize();
        assert_eq!(cfg.stack_budget, 8192);
        assert_eq!(cfg.rules.len(), 3);
        // 1. 命中启用规则 #0 (level = 3)
        let valid_key = b"Bearer sk-live-1234567890abcdef12345678";
        assert_eq!(cfg.decide(valid_key), Some(3));
        // 2. 命中排除规则 #2 (含 "sk-live-00"，优先排除)
        let excluded_key = b"Bearer sk-live-0034567890abcdef12345678";
        assert_eq!(cfg.decide(excluded_key), None);
        // 3. 长度不足 24，跳过规则 #0，但命中规则 #1 (Base64Rule, level = 2)
        let short_key = b"sk-live-short";
        assert_eq!(cfg.decide(short_key), Some(2));
        // 4. 未命中任何规则且 other_pct = 0
        assert_eq!(cfg.decide(b"hello world"), None);
    }

    #[test]
    fn test_stack_budget_default_and_clamp() {
        let mut default_cfg = BytesObfuscationConfig::default();
        default_cfg.finalize();
        assert_eq!(default_cfg.stack_budget, DEFAULT_STACK_BUDGET);

        let toml_str = r#"
            stack_budget = 999999
        "#;
        let mut over_cfg: BytesObfuscationConfig = toml::from_str(toml_str).unwrap();
        over_cfg.finalize();
        assert_eq!(over_cfg.stack_budget, MAX_STACK_BUDGET);
    }

    #[test]
    fn test_mutual_exclusion_validation() {
        // 同时指定 substrings 和 subbytesarr 应当被 finalize 剔除
        let toml_str = r#"
            [[rules]]
            name = "InvalidBoth"
            substrings = ["abc"]
            subbytesarr = [0x61, 0x62, 0x63]
            [[rules]]
            name = "InvalidNone"
            min_len = 4
        "#;
        let mut cfg: BytesObfuscationConfig = toml::from_str(toml_str).unwrap();
        cfg.finalize();
        assert!(cfg.rules.is_empty());
    }
}

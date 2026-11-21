// src/all_pass/remove_leak.rs
use std::sync::LazyLock;

use lib_unknown::rand::core::fill_bytes;
use llvm_pass::inkwell::values::{AsValueRef, BasicValueEnum};
use llvm_pass::{ModulePass, ModuleRef, PreservedAnalyses};
use llvm_pass::llvm_sys::core::LLVMIsAConstantDataArray;
use regex::bytes::Regex;

use crate::utils::conf::{CONFIG, LeakRuleConfig};
use crate::*;

const PASS_NAME: &str = "RemoveLeak";

static RULESET: LazyLock<RuleSet> = LazyLock::new(RuleSet::from_config);

struct CompiledRule {
    name: &'static str,
    min_len: usize,
    max_len: usize,
    substrings: Vec<&'static [u8]>,
    regex: Regex,
}

impl CompiledRule {
    fn from_static_config(cfg: &'static LeakRuleConfig) -> Option<Self> {
        let min_len = cfg.min_len.max(1);
        let max_len = cfg.max_len.unwrap_or(usize::MAX);

        if min_len > max_len {
            pwarn!(
                PASS_NAME,
                "规则 [{}] 的 min_len ({}) > max_len ({})，已跳过。",
                cfg.name,
                min_len,
                max_len
            );
            return None;
        }

        let substrings: Vec<&'static [u8]> = cfg
            .substrings
            .iter()
            .map(|s| s.as_bytes())
            .filter(|s| !s.is_empty())
            .collect();

        match Regex::new(&cfg.regex) {
            Ok(regex) => Some(Self {
                name: &cfg.name,
                min_len,
                max_len,
                substrings,
                regex,
            }),
            Err(error) => {
                pwarn!(
                    PASS_NAME,
                    "规则 [{}] 正则编译失败，已跳过: {} (错误: {})",
                    cfg.name,
                    cfg.regex,
                    error
                );
                None
            }
        }
    }

    #[inline]
    fn might_match(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        if len < self.min_len || len > self.max_len {
            return false;
        }
        if self.substrings.is_empty() {
            return true;
        }
        self.substrings
            .iter()
            .any(|&sub| contains_subslice(bytes, sub))
    }
}

struct RuleSet {
    enabled: bool,
    rules: Vec<CompiledRule>,
    global_min_len: usize,
    global_max_len: usize,
}

impl RuleSet {
    fn from_config() -> Self {
        let cfg = &CONFIG.remove_leak;
        if !cfg.enabled {
            return Self {
                enabled: false,
                rules: Vec::new(),
                global_min_len: usize::MAX,
                global_max_len: 0,
            };
        }

        let rules: Vec<CompiledRule> = cfg
            .rules
            .iter()
            .filter_map(CompiledRule::from_static_config)
            .collect();

        let global_min_len = rules.iter().map(|r| r.min_len).min().unwrap_or(usize::MAX);
        let global_max_len = rules.iter().map(|r| r.max_len).max().unwrap_or(0);

        Self {
            enabled: true,
            rules,
            global_min_len,
            global_max_len,
        }
    }

    /// Level 0 全局长度快筛
    #[inline]
    fn might_match_any(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        len >= self.global_min_len && len <= self.global_max_len
    }
}

/// 利用标准库针对 `u8` 特化的 SIMD 首字节检索实现零分配快速子串匹配
#[inline]
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    let first = needle[0];
    let rest = &needle[1..];
    let max_start = haystack.len() - needle.len();
    let mut pos = 0;

    while pos <= max_start {
        let Some(offset) = haystack[pos..=max_start].iter().position(|&b| b == first) else {
            return false;
        };
        let idx = pos + offset;
        if haystack[idx + 1..idx + 1 + rest.len()] == *rest {
            return true;
        }
        pos = idx + 1;
    }
    false
}

/// 四级漏斗扫描 + 写时拷贝原地擦除
fn scrub_bytes<'a>(
    raw_bytes: &[u8],
    scratch_buf: &'a mut Vec<u8>,
    ruleset: &RuleSet,
    tag: &str,
    module: &ModuleRef<'_>,
) -> Option<&'a [u8]> {
    if !ruleset.might_match_any(raw_bytes) {
        return None;
    }

    let mut modified = false;

    for rule in &ruleset.rules {
        let candidate: &[u8] = if modified {
            scratch_buf.as_slice()
        } else {
            raw_bytes
        };

        if !rule.might_match(candidate) {
            continue;
        }

        let mut search_offset = 0usize;
        loop {
            let current_bytes: &[u8] = if modified {
                scratch_buf.as_slice()
            } else {
                raw_bytes
            };

            if search_offset >= current_bytes.len() {
                break;
            }

            let Some(found) = rule.regex.find_at(current_bytes, search_offset) else {
                break;
            };

            let match_pos = found.start();
            let match_end = found.end();
            if match_pos == match_end {
                search_offset = match_pos.saturating_add(1);
                continue;
            }

            if !modified {
                scratch_buf.clear();
                scratch_buf.extend_from_slice(raw_bytes);
                modified = true;
            }

            pdebug!(
                tag,
                module,
                "Found [{}]: {}",
                rule.name,
                String::from_utf8_lossy(&scratch_buf[match_pos..match_end])
            );

            let target = &mut scratch_buf[match_pos..match_end];
            fill_bytes(target);
            for byte in target {
                *byte = b'a' + (*byte % 26);
            }

            search_offset = match_end;
        }
    }

    if modified {
        Some(scratch_buf.as_slice())
    } else {
        None
    }
}

pub struct RemoveLeakPass;

impl ModulePass for RemoveLeakPass {
    fn name(&self) -> &str {
        PASS_NAME
    }

    fn run(&mut self, module: &mut ModuleRef<'_>) -> PreservedAnalyses {
        let tag = self.name();
        let ruleset = &*RULESET;

        if !ruleset.enabled {
            pdebug!(tag, module, "Pass 已在配置中禁用，跳过。");
            return PreservedAnalyses::All;
        }
        if ruleset.rules.is_empty() {
            pwarn!(tag, module, "没有可用的规则，跳过 pass。");
            return PreservedAnalyses::All;
        }
        // unsafe {
        //     llvm_pass::llvm_sys::core::LLVMSetSourceFileName(module.as_raw_ptr(), c"".as_ptr(), 0);
        // }

        let inkwell_module = module.as_inkwell();
        let m = &*inkwell_module;
        let context = m.get_context();

        let mut scratch_buf = Vec::with_capacity(256);
        let mut scrubbed_globals = 0usize;

        for global in m.get_globals() {
            let Some(BasicValueEnum::ArrayValue(array)) = global.get_initializer() else {
                continue;
            };
            if unsafe { LLVMIsAConstantDataArray(array.as_value_ref()).is_null() } {
                continue;
            }
            if !array.is_const_string() {
                continue;
            }
            let Some(raw_bytes) = array.as_const_string() else {
                continue;
            };

            if let Some(scrubbed) = scrub_bytes(raw_bytes, &mut scratch_buf, ruleset, tag, module) {
                let new_constant = context.const_string(scrubbed, false);
                global.set_initializer(&new_constant);
                scrubbed_globals += 1;
            }
        }

        if scrubbed_globals > 0 {
            pinfo!(
                tag,
                module,
                "已清理 {} 个敏感字符串常量。",
                scrubbed_globals
            );
            PreservedAnalyses::PreserveCFG
                .preserve::<CallGraphAnalysis>()
                .preserve::<GlobalsAA>()
                .preserve_function_analyses_proxy()
        } else {
            pdebug!(tag, module, "当前模块没有需要清理的字符串。");
            PreservedAnalyses::All
        }
    }
}

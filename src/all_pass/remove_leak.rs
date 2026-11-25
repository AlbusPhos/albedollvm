// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// src/all_pass/remove_leak.rs

use lib_unknown::rand::core::fill_bytes;
use llvm_pass::inkwell::values::{AsValueRef, BasicValueEnum};
use llvm_pass::llvm_sys::core::LLVMIsAConstantDataArray;
use llvm_pass::{ModulePass, ModuleRef, PreservedAnalyses};

use crate::utils::conf::{CONFIG, remove_leak::RemoveLeakConfig};
use crate::*;

const PASS_NAME: &str = "RemoveLeak";

/// 写时拷贝原地擦除
fn scrub_bytes<'a>(
    raw_bytes: &[u8],
    scratch_buf: &'a mut Vec<u8>,
    cfg: &RemoveLeakConfig,
    tag: &str,
    module: &ModuleRef<'_>,
) -> Option<&'a [u8]> {
    if !cfg.might_match_any(raw_bytes) {
        return None;
    }

    let mut modified = false;

    for rule in &cfg.rules {
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

            let Some(found) = rule.find_at(current_bytes, search_offset) else {
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
        let cfg = &CONFIG.remove_leak;

        if !cfg.enabled {
            pdebug!(tag, module, "Pass 已在配置中禁用，跳过。");
            return PreservedAnalyses::All;
        }

        if cfg.rules.is_empty() {
            pwarn!(tag, module, "没有可用的规则，跳过 pass。");
            return PreservedAnalyses::All;
        }

        let inkwell_module = module.as_inkwell();
        let m = &*inkwell_module;
        let context = m.get_context();

        let mut scratch_buf = Vec::with_capacity(256);
        let mut scrubbed_globals = 0usize;

        m.set_source_file_name("");

        for global in m.get_globals() {
            let Some(BasicValueEnum::ArrayValue(array)) = global.get_initializer() else {
                continue;
            };

            if unsafe { LLVMIsAConstantDataArray(array.as_value_ref()).is_null() } {
                continue;
            }

            let Some(raw_bytes) = array.as_const_string() else {
                continue;
            };

            if let Some(scrubbed) = scrub_bytes(raw_bytes, &mut scratch_buf, cfg, tag, module) {
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

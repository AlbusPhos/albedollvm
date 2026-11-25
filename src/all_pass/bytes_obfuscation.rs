// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// src/all_pass/bytes_obfuscation.rs

use llvm_pass::inkwell::memory_buffer::MemoryBuffer;
use llvm_pass::inkwell::module::Linkage;
use llvm_pass::inkwell::values::{
    AsValueRef, BasicValue, BasicValueEnum, GlobalValue, InstructionValue,
};
use llvm_pass::llvm_sys::core::{
    LLVMContextSetDiscardValueNames, LLVMContextShouldDiscardValueNames, LLVMCountIncoming,
    LLVMDeleteGlobal, LLVMGetBasicBlockParent, LLVMGetBasicBlockTerminator, LLVMGetEntryBasicBlock,
    LLVMGetFirstBasicBlock, LLVMGetFirstInstruction, LLVMGetFirstUse, LLVMGetIncomingBlock,
    LLVMGetIncomingValue, LLVMGetInstructionOpcode, LLVMGetInstructionParent, LLVMGetModuleContext,
    LLVMGetNextBasicBlock, LLVMGetNextInstruction, LLVMGetNextUse, LLVMGetNumArgOperands,
    LLVMGetNumOperands, LLVMGetNumSuccessors, LLVMGetOperand, LLVMGetSuccessor, LLVMGetTypeKind,
    LLVMGetUser, LLVMIsAConstantDataArray, LLVMIsAInstruction, LLVMSetOperand, LLVMTypeOf,
};
use llvm_pass::llvm_sys::linker::LLVMLinkModules2;
use llvm_pass::llvm_sys::prelude::{LLVMBasicBlockRef, LLVMBool, LLVMModuleRef, LLVMValueRef};
use llvm_pass::llvm_sys::{LLVMOpcode, LLVMTypeKind};
use llvm_pass::{ModulePass, ModuleRef, PreservedAnalyses};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::utils::conf::CONFIG;
use crate::utils::rs2ir;
use crate::*;

const PASS_NAME: &str = "BytesObfuscation";

struct Candidate<'ctx> {
    global: GlobalValue<'ctx>,
    name: String,
    bytes: Vec<u8>,
    level: u8,
    /// true: `fn() -> *const u8` (OnceLock 静态堆驻留)
    /// false: `fn(out_buf: *mut u8, buf_len: usize) -> i32` (栈上临时缓冲区解密)
    lazy: bool,
    /// 是否通过了栈解密安全初筛（全部为直接指令引用、无指针逃逸、不在 WinEH 内且单串长度 <= stack_budget）
    stack_eligible: bool,
    /// 引用该常量的所有指令级 User（去重）
    inst_users: Vec<LLVMValueRef>,
}

/// 收集全局常量的所有指令级 User（去重），并判断是否全部为直接指令引用
fn collect_instruction_users(global_ref: LLVMValueRef) -> (Vec<LLVMValueRef>, bool) {
    let mut inst_users = Vec::new();
    let mut seen_users = FxHashSet::default();
    let mut all_direct_inst = true;
    unsafe {
        let mut use_ref = LLVMGetFirstUse(global_ref);
        while !use_ref.is_null() {
            let next_use = LLVMGetNextUse(use_ref);
            let user = LLVMGetUser(use_ref);
            if !user.is_null() && !LLVMIsAInstruction(user).is_null() {
                if seen_users.insert(user) {
                    inst_users.push(user);
                }
            } else {
                // 存在 ConstantExpr 或全局聚合体初始化器等非指令级引用
                all_direct_inst = false;
            }
            use_ref = next_use;
        }
    }
    (inst_users, all_direct_inst)
}

/// 检测指令是否处于 MSVC WinEH 的 funclet (catchpad / cleanuppad) 可达区域内
unsafe fn instruction_in_funclet_region(inst: LLVMValueRef) -> bool {
    unsafe {
        let block = LLVMGetInstructionParent(inst);
        if block.is_null() {
            return true;
        }
        let function = LLVMGetBasicBlockParent(block);
        if function.is_null() {
            return true;
        }
        let mut eh_pad_blocks: Vec<LLVMBasicBlockRef> = Vec::new();
        let mut bb = LLVMGetFirstBasicBlock(function);
        while !bb.is_null() {
            let mut first = LLVMGetFirstInstruction(bb);
            while !first.is_null() && LLVMGetInstructionOpcode(first) == LLVMOpcode::LLVMPHI {
                first = LLVMGetNextInstruction(first);
            }
            if !first.is_null()
                && matches!(
                    LLVMGetInstructionOpcode(first),
                    LLVMOpcode::LLVMCatchPad | LLVMOpcode::LLVMCleanupPad
                )
            {
                eh_pad_blocks.push(bb);
            }
            bb = LLVMGetNextBasicBlock(bb);
        }
        if eh_pad_blocks.is_empty() {
            return false;
        }
        let mut visited = FxHashSet::default();
        let mut worklist = eh_pad_blocks;
        while let Some(current) = worklist.pop() {
            if !visited.insert(current as usize) {
                continue;
            }
            if current == block {
                return true;
            }
            let terminator = LLVMGetBasicBlockTerminator(current);
            if terminator.is_null() {
                continue;
            }
            for i in 0..LLVMGetNumSuccessors(terminator) {
                let successor = LLVMGetSuccessor(terminator, i);
                if !successor.is_null() {
                    worklist.push(successor);
                }
            }
        }
        false
    }
}

/// 判定单个指令级 User 是否满足非 Lazy（栈上分配 `alloca`）的安全条件
unsafe fn is_user_safe_for_stack_decryption(user: LLVMValueRef, global_ref: LLVMValueRef) -> bool {
    unsafe {
        let block = LLVMGetInstructionParent(user);
        if block.is_null() || LLVMGetBasicBlockParent(block).is_null() {
            return false;
        }
        // 检查是否携带 Token 操作数（如 MSVC funclet bundle）
        let num_ops = LLVMGetNumOperands(user);
        for i in 0..num_ops {
            let op = LLVMGetOperand(user, i as u32);
            if !op.is_null() && LLVMGetTypeKind(LLVMTypeOf(op)) == LLVMTypeKind::LLVMTokenTypeKind {
                return false;
            }
        }
        if instruction_in_funclet_region(user) {
            return false;
        }
        // 按指令 Opcode 检查指针逃逸风险
        match LLVMGetInstructionOpcode(user) {
            // 直接读取字节或比较地址：绝对不会逃逸，完全安全
            LLVMOpcode::LLVMLoad | LLVMOpcode::LLVMICmp => true,
            // 函数调用：确保不是被调用的函数指针本身，且不会通过返回值/全局变量逃逸
            LLVMOpcode::LLVMCall => {
                let num_args = LLVMGetNumArgOperands(user);
                // 排除 global_ref 被当作被调函数指针的极端情况
                LLVMGetOperand(user, num_args) != global_ref
            }
            // Store 指令：`store Val, Ptr`
            // 如果 global_ref 是 operand(0) (Val)，说明正在把指针写入某个内存槽（如结构体字段或返回槽），会逃逸！
            LLVMOpcode::LLVMStore => LLVMGetOperand(user, 0) != global_ref,
            // Ret / PHI / Select / Invoke 等：在 Rust 中极易用于向上返回 &'static 切片，保守回退至 lazy = true
            _ => false,
        }
    }
}

/// 初筛该常量是否具备参与非 Lazy（栈缓冲区模式）预算分配的资格
fn is_eligible_for_stack_budget(
    bytes_len: usize,
    stack_budget: usize,
    all_direct_inst: bool,
    inst_users: &[LLVMValueRef],
    global_ref: LLVMValueRef,
) -> bool {
    if !all_direct_inst || bytes_len == 0 || bytes_len > stack_budget || inst_users.is_empty() {
        return false;
    }
    unsafe {
        inst_users
            .iter()
            .all(|&u| is_user_safe_for_stack_decryption(u, global_ref))
    }
}

/// 在目标函数的 Entry Block 最顶部（跳过已有的 Alloca）定位 Builder，确保支配所有使用点
unsafe fn position_builder_at_entry_alloca(
    builder: &inkwell::builder::Builder,
    func_ref: LLVMValueRef,
) -> bool {
    unsafe {
        let entry_bb = LLVMGetEntryBasicBlock(func_ref);
        if entry_bb.is_null() {
            return false;
        }
        let mut inst = LLVMGetFirstInstruction(entry_bb);
        while !inst.is_null() && LLVMGetInstructionOpcode(inst) == LLVMOpcode::LLVMAlloca {
            inst = LLVMGetNextInstruction(inst);
        }
        if inst.is_null() {
            return false;
        }
        let target_inst = InstructionValue::new(inst);
        builder.position_before(&target_inst);
        true
    }
}

pub struct BytesObfuscationPass;

impl ModulePass for BytesObfuscationPass {
    fn name(&self) -> &str {
        PASS_NAME
    }

    fn run(&mut self, module: &mut ModuleRef<'_>) -> PreservedAnalyses {
        let tag = self.name();
        let cfg = &CONFIG.bytes_obfuscation;
        if !cfg.enabled {
            pdebug!(tag, module, "Pass 已在配置中禁用，跳过。");
            return PreservedAnalyses::All;
        }

        let stack_budget = cfg.stack_budget;
        let inkwell_module = module.as_inkwell();
        let context = inkwell_module.get_context();

        // ==================== 扫描全模块候选常量并完成安全初筛 ====================
        let mut candidates = Vec::new();
        for global in inkwell_module.get_globals() {
            if !global.is_constant() {
                continue;
            }
            let g_name_ref = global.get_name().to_str().unwrap_or("");
            if g_name_ref.starts_with("_llvm_bytes_") || g_name_ref.starts_with("llvm.") {
                continue;
            }
            let array = match global.get_initializer() {
                Some(BasicValueEnum::ArrayValue(arr)) => arr,
                Some(BasicValueEnum::StructValue(st)) if st.count_fields() == 1 => {
                    let Some(BasicValueEnum::ArrayValue(arr)) = st.get_field_at_index(0) else {
                        continue;
                    };
                    arr
                }
                _ => continue,
            };
            if unsafe { LLVMIsAConstantDataArray(array.as_value_ref()).is_null() } {
                continue;
            }
            let Some(raw_bytes) = array.as_const_string() else {
                continue;
            };
            if raw_bytes.is_empty() {
                continue;
            }
            let global_ref = global.as_value_ref();
            let (inst_users, all_direct_inst) = collect_instruction_users(global_ref);
            if inst_users.is_empty() {
                continue;
            }
            if let Some(level) = cfg.decide(raw_bytes) {
                let stack_eligible = is_eligible_for_stack_budget(
                    raw_bytes.len(),
                    stack_budget,
                    all_direct_inst,
                    &inst_users,
                    global_ref,
                );
                candidates.push(Candidate {
                    global,
                    name: g_name_ref.to_owned(),
                    bytes: raw_bytes.to_vec(),
                    level,
                    lazy: true, // 默认设为 Lazy，在阶段 2 竞标栈预算成功后切换为 false
                    stack_eligible,
                    inst_users,
                });
            }
        }

        if candidates.is_empty() {
            pdebug!(tag, module, "当前模块没有需要混淆的字节串常量。");
            return PreservedAnalyses::All;
        }

        // ==================== 按“价值密度”优先级贪心分配单函数栈预算 ====================
        let mut eligible_indices: Vec<usize> = (0..candidates.len())
            .filter(|&i| candidates[i].stack_eligible)
            .collect();
        eligible_indices.sort_by(|&a, &b| {
            let ca = &candidates[a];
            let cb = &candidates[b];
            cb.level
                .cmp(&ca.level)
                .then_with(|| ca.bytes.len().cmp(&cb.bytes.len()))
                .then_with(|| ca.inst_users.len().cmp(&cb.inst_users.len()))
        });

        let mut func_stack_used: FxHashMap<LLVMValueRef, usize> = FxHashMap::default();

        for idx in eligible_indices {
            let c = &mut candidates[idx];
            let bytes_len = c.bytes.len();

            let mut parent_fns: Vec<LLVMValueRef> = Vec::new();
            let mut valid = true;
            unsafe {
                for &user in &c.inst_users {
                    let bb = LLVMGetInstructionParent(user);
                    let func = if bb.is_null() {
                        std::ptr::null_mut()
                    } else {
                        LLVMGetBasicBlockParent(bb)
                    };
                    if func.is_null() {
                        valid = false;
                        break;
                    }
                    if !parent_fns.contains(&func) {
                        parent_fns.push(func);
                    }
                }
            }
            if !valid || parent_fns.is_empty() {
                continue;
            }

            let can_fit_all = parent_fns.iter().all(|&func| {
                let used = func_stack_used.get(&func).copied().unwrap_or(0);
                used.saturating_add(bytes_len) <= stack_budget
            });

            if can_fit_all {
                for func in parent_fns {
                    *func_stack_used.entry(func).or_insert(0) += bytes_len;
                }
                c.lazy = false;
            }
        }

        let non_lazy_count = candidates.iter().filter(|c| !c.lazy).count();
        pinfo!(
            tag,
            module,
            "发现 {} 个待混淆字节串（其中 {} 个启用非 Lazy 栈解密，{} 个使用 Lazy 静态堆解密，单函数栈预算 = {} B），开始批量构建 IR...",
            candidates.len(),
            non_lazy_count,
            candidates.len() - non_lazy_count,
            stack_budget
        );

        // ==================== 批量合成并链接解密函数 IR ====================
        // 对具有完全相同 (字节内容, 混淆等级, lazy模式) 的常量复用同一个解密函数
        let mut fn_codes = Vec::with_capacity(candidates.len());
        let mut dedup_map: FxHashMap<(&[u8], u8, bool), String> = FxHashMap::default();
        let mut target_fns = Vec::with_capacity(candidates.len());
        for c in &candidates {
            let key = (c.bytes.as_slice(), c.level, c.lazy);
            let fn_name = if let Some(existing_fn) = dedup_map.get(&key) {
                existing_fn.clone()
            } else {
                let (code, name, _) = rs2ir::bytes2fn(&c.bytes, c.level, c.lazy);
                fn_codes.push(code);
                dedup_map.insert(key, name.clone());
                name
            };
            target_fns.push(fn_name);
        }

        let mut ir_str = match rs2ir::to_ir(&fn_codes) {
            Ok(ir) => ir,
            Err(err) => {
                perror!(tag, module, "生成混淆 LLVM IR 失败: {}", err);
                return PreservedAnalyses::All;
            }
        };
        ir_str.push('\0');
        let ir_bytes = &ir_str.as_bytes()[..ir_str.len() - 1];
        let mem_buf = MemoryBuffer::create_from_memory_range(ir_bytes, "obf_ir");
        let obf_mod = unsafe {
            let ctx_ref = LLVMGetModuleContext(inkwell_module.as_mut_ptr());
            let prev_discard = LLVMContextShouldDiscardValueNames(ctx_ref);
            if prev_discard != 0 {
                LLVMContextSetDiscardValueNames(ctx_ref, 0);
            }
            let parse_res = context.create_module_from_ir(mem_buf);
            if prev_discard != 0 {
                LLVMContextSetDiscardValueNames(ctx_ref, prev_discard);
            }
            match parse_res {
                Ok(m) => m,
                Err(err) => {
                    perror!(
                        tag,
                        module,
                        "解析混淆 IR 到临时 Module 失败: {}",
                        err.to_string()
                    );
                    return PreservedAnalyses::All;
                }
            }
        };

        let mut newly_linked_fns = Vec::new();
        for func in obf_mod.get_functions() {
            if func.count_basic_blocks() > 0 && func.get_linkage() == Linkage::External {
                if let Ok(name) = func.get_name().to_str() {
                    if inkwell_module
                        .get_function(name)
                        .is_none_or(|f| f.count_basic_blocks() == 0)
                    {
                        newly_linked_fns.push(name.to_owned());
                    }
                }
            }
        }
        let mut newly_linked_gvs = Vec::new();
        for gv in obf_mod.get_globals() {
            if gv.get_initializer().is_some() && gv.get_linkage() == Linkage::External {
                if let Ok(name) = gv.get_name().to_str() {
                    if inkwell_module
                        .get_global(name)
                        .is_none_or(|g| g.get_initializer().is_none())
                    {
                        newly_linked_gvs.push(name.to_owned());
                    }
                }
            }
        }

        unsafe {
            let src_ref: LLVMModuleRef = obf_mod.as_mut_ptr();
            let dst_ref: LLVMModuleRef = inkwell_module.as_mut_ptr();
            std::mem::forget(obf_mod);
            let link_err: LLVMBool = LLVMLinkModules2(dst_ref, src_ref);
            if link_err != 0 {
                perror!(tag, module, "链接混淆 IR 到宿主模块失败！");
                return PreservedAnalyses::All;
            }
        }

        // 链接完成后，在宿主模块中将新导入的混淆函数与全局变量收敛为 InternalLinkage
        for name in &newly_linked_fns {
            if let Some(func) = inkwell_module.get_function(name) {
                func.set_linkage(Linkage::Internal);
            }
        }
        for name in &newly_linked_gvs {
            if let Some(gv) = inkwell_module.get_global(name) {
                gv.set_linkage(Linkage::Internal);
            }
        }

        // ==================== 注入解密调用并替换指令操作数 ====================
        let builder = context.create_builder();
        let mut replaced_globals = 0usize;
        let mut replaced_uses = 0usize;

        for (c, fn_name) in candidates.into_iter().zip(target_fns) {
            let Some(decrypt_fn) = inkwell_module.get_function(&fn_name) else {
                pwarn!(
                    tag,
                    module,
                    "未能在链接后的模块中找到解密函数 {} (对应常量 {})",
                    fn_name,
                    c.name
                );
                continue;
            };
            let global_ref: LLVMValueRef = c.global.as_value_ref();

            if !c.lazy {
                // ==================== 分支 A：非 Lazy 模式（栈上 alloca 解密） ====================
                // 函数签名: fn(out_buf: *mut u8, buf_len: usize) -> i32
                let array_ty = context.i8_type().array_type(c.bytes.len() as u32);
                let Some(usize_param) = decrypt_fn.get_nth_param(1) else {
                    continue;
                };
                let usize_ty = usize_param.get_type().into_int_type();
                let len_val = usize_ty.const_int(c.bytes.len() as u64, false);

                let mut func_alloca_cache: FxHashMap<LLVMValueRef, BasicValueEnum<'_>> =
                    FxHashMap::default();

                for user in c.inst_users {
                    unsafe {
                        let parent_bb = LLVMGetInstructionParent(user);
                        if parent_bb.is_null() {
                            continue;
                        }
                        let parent_fn = LLVMGetBasicBlockParent(parent_bb);
                        if parent_fn.is_null() {
                            continue;
                        }
                        let stack_buf = if let Some(&cached_buf) = func_alloca_cache.get(&parent_fn)
                        {
                            cached_buf
                        } else {
                            if !position_builder_at_entry_alloca(&builder, parent_fn) {
                                continue;
                            }
                            let Ok(alloca_ptr) = builder.build_alloca(array_ty, "obf_stack_buf")
                            else {
                                continue;
                            };
                            let buf_val = alloca_ptr.as_basic_value_enum();
                            func_alloca_cache.insert(parent_fn, buf_val);
                            buf_val
                        };

                        let inst = InstructionValue::new(user);
                        builder.position_before(&inst);
                        if builder
                            .build_call(decrypt_fn, &[stack_buf.into(), len_val.into()], "")
                            .is_err()
                        {
                            pwarn!(tag, module, "构建非 Lazy 栈解密调用失败: {}", fn_name);
                            continue;
                        }

                        let stack_buf_ref = stack_buf.as_value_ref();
                        let num_ops = LLVMGetNumOperands(user);
                        for idx in 0..num_ops {
                            let idx = idx as u32;
                            if LLVMGetOperand(user, idx) == global_ref {
                                LLVMSetOperand(user, idx, stack_buf_ref);
                                replaced_uses += 1;
                            }
                        }
                    }
                }
            } else {
                // ==================== 分支 B：Lazy 回退模式（OnceLock 静态堆缓冲区） ====================
                // 函数签名: fn() -> *const u8
                for user in c.inst_users {
                    unsafe {
                        if LLVMGetInstructionOpcode(user) == LLVMOpcode::LLVMPHI {
                            let mut phi_bb_cache: FxHashMap<LLVMBasicBlockRef, LLVMValueRef> =
                                FxHashMap::default();
                            let incoming_count = LLVMCountIncoming(user);
                            for idx in 0..incoming_count {
                                if LLVMGetIncomingValue(user, idx) != global_ref {
                                    continue;
                                }
                                let incoming_bb = LLVMGetIncomingBlock(user, idx);
                                if incoming_bb.is_null() {
                                    continue;
                                }
                                let call_val_ref =
                                    if let Some(&cached) = phi_bb_cache.get(&incoming_bb) {
                                        cached
                                    } else {
                                        let terminator = LLVMGetBasicBlockTerminator(incoming_bb);
                                        if terminator.is_null() {
                                            continue;
                                        }
                                        let term_inst = InstructionValue::new(terminator);
                                        builder.position_before(&term_inst);
                                        let Ok(call_site) =
                                            builder.build_call(decrypt_fn, &[], "obf_bytes")
                                        else {
                                            continue;
                                        };
                                        let Some(call_val) = call_site.try_as_basic_value().basic()
                                        else {
                                            continue;
                                        };
                                        let val_ref = call_val.as_basic_value_enum().as_value_ref();
                                        phi_bb_cache.insert(incoming_bb, val_ref);
                                        val_ref
                                    };
                                LLVMSetOperand(user, idx, call_val_ref);
                                replaced_uses += 1;
                            }
                        } else {
                            let inst = InstructionValue::new(user);
                            builder.position_before(&inst);
                            let Ok(call_site) = builder.build_call(decrypt_fn, &[], "obf_bytes")
                            else {
                                continue;
                            };
                            let Some(call_val) = call_site.try_as_basic_value().basic() else {
                                continue;
                            };
                            let call_val_ref = call_val.as_basic_value_enum().as_value_ref();
                            let num_ops = LLVMGetNumOperands(user);
                            for idx in 0..num_ops {
                                let idx = idx as u32;
                                if LLVMGetOperand(user, idx) == global_ref {
                                    LLVMSetOperand(user, idx, call_val_ref);
                                    replaced_uses += 1;
                                }
                            }
                        }
                    }
                }
            }

            // 若该全局常量已无任何残留引用，则彻底删除明文常量
            unsafe {
                if LLVMGetFirstUse(global_ref).is_null() {
                    LLVMDeleteGlobal(global_ref);
                    replaced_globals += 1;
                } else {
                    pdebug!(
                        tag,
                        module,
                        "全局常量 {} 仍存在非指令级引用，保留原符号以保证 IR 合法。",
                        c.name
                    );
                }
            }
        }

        pinfo!(
            tag,
            module,
            "字节串混淆完成：成功替换 {} 处指令引用，彻底抹除 {} 个明文全局常量。",
            replaced_uses,
            replaced_globals
        );
        PreservedAnalyses::None
    }
}

// src/all_pass/rust_remove_panic.rs
use std::fmt::Write as _;
use std::sync::LazyLock;
use std::{ptr, slice};

use llvm_pass::inkwell::attributes::{Attribute, AttributeLoc};
use llvm_pass::inkwell::builder::Builder;
use llvm_pass::inkwell::context::ContextRef;
use llvm_pass::inkwell::module::{Linkage, Module};
use llvm_pass::inkwell::types::{AsTypeRef, FunctionType};
use llvm_pass::inkwell::values::{
    AsValueRef, BasicMetadataValueEnum, BasicValue, BasicValueEnum, CallSiteValue, FunctionValue,
    InstructionOpcode, InstructionValue,
};
use llvm_pass::inkwell::{DLLStorageClass, GlobalVisibility};
use llvm_pass::llvm_sys::core::{
    LLVMBuildCallWithOperandBundles, LLVMCreateBuilderInContext, LLVMDisposeBuilder,
    LLVMDisposeOperandBundle, LLVMGetCalledValue, LLVMGetFunctionCallConv, LLVMGetGlobalParent,
    LLVMGetModuleContext, LLVMGetNumOperandBundles, LLVMGetOperandBundleAtIndex,
    LLVMPositionBuilderBefore, LLVMSetInstructionCallConv,
};
use llvm_pass::llvm_sys::prelude::{LLVMContextRef, LLVMOperandBundleRef};
use llvm_pass::{
    AnyValueExt, FunctionExt, InstructionExt, ModulePass, ModuleRef, PreservedAnalyses,
};
use regex::Regex;
use rustc_demangle::try_demangle;

use crate::utils::conf::{CONFIG, PanicMode};
use crate::*;

static PANIC_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"core(?:\[[0-9a-f]+])?::panicking\b|::panic_fmt$|\bpanic_(?:bounds_check|display|const|nounwind)\b|\brust_begin_unwind\b|\b__rust_start_panic\b|\brust_panic_with_hook\b|::begin_panic\b|\b(?:unwrap|expect|assert)_failed\b",
    )
        .expect("built-in RemovePanic regex")
});

#[inline]
fn might_be_panic_symbol(raw_name: &str) -> bool {
    raw_name.contains("panic") || raw_name.contains("unwind") || raw_name.contains("_failed")
}

fn is_panic_related(function: FunctionValue<'_>, demangle_buf: &mut String) -> bool {
    let name = function.get_name().to_string_lossy();
    if !might_be_panic_symbol(&name) {
        return false;
    }
    let candidate = match try_demangle(&name) {
        Ok(demangled) => {
            demangle_buf.clear();
            let _ = write!(demangle_buf, "{demangled:#}");
            demangle_buf.as_str()
        }
        Err(_) => name.as_ref(),
    };
    PANIC_PATTERN.is_match(candidate)
}

#[inline]
fn enum_attr(ctx: ContextRef<'_>, name: &str) -> Attribute {
    ctx.create_enum_attribute(Attribute::get_named_enum_kind_id(name), 0)
}

#[derive(Clone, Copy)]
struct Terminator<'ctx> {
    ctx: ContextRef<'ctx>,
    raw_ctx: LLVMContextRef,
    callee_fn: FunctionValue<'ctx>,
    callee_ty: FunctionType<'ctx>,
    /// `Exit` 模式下为 `Some(exit_code)`，`Trap` 模式下为 `None`
    exit_arg: Option<BasicValueEnum<'ctx>>,
    noreturn_attr: Attribute,
    has_expected_ty: bool,
}

impl<'ctx> Terminator<'ctx> {
    fn new(module: &Module<'ctx>, ctx: ContextRef<'ctx>) -> Self {
        let cfg = &CONFIG.rust_remove_panic;

        let (fn_name, callee_ty, exit_arg) = match cfg.mode {
            PanicMode::Exit => {
                let i32_ty = ctx.i32_type();
                let fn_ty = ctx.void_type().fn_type(&[i32_ty.into()], false);
                let arg = i32_ty
                    .const_int(cfg.exit_code as u64, false)
                    .as_basic_value_enum();
                ("exit", fn_ty, Some(arg))
            }
            PanicMode::Trap => {
                let fn_ty = ctx.void_type().fn_type(&[], false);
                ("llvm.trap", fn_ty, None)
            }
        };

        let callee_fn = match module.get_function(fn_name) {
            Some(function) => function,
            None => module.add_function(fn_name, callee_ty, None),
        };

        let noreturn_attr = enum_attr(ctx, "noreturn");
        let nounwind_attr = enum_attr(ctx, "nounwind");
        let cold_attr = enum_attr(ctx, "cold");
        callee_fn.add_attribute(AttributeLoc::Function, noreturn_attr);
        callee_fn.add_attribute(AttributeLoc::Function, nounwind_attr);
        callee_fn.add_attribute(AttributeLoc::Function, cold_attr);

        let has_expected_ty = callee_fn.get_type() == callee_ty;
        // SAFETY: `callee_fn` 是当前模块中的 GlobalValue，直接获取其所属 Module 的 LLVMContextRef
        let raw_ctx =
            unsafe { LLVMGetModuleContext(LLVMGetGlobalParent(callee_fn.as_value_ref())) };

        Self {
            ctx,
            raw_ctx,
            callee_fn,
            callee_ty,
            exit_arg,
            noreturn_attr,
            has_expected_ty,
        }
    }

    /// 零分配获取参数切片（Exit 模式返回长度 1 切片，Trap 模式返回空切片）
    #[inline]
    fn basic_args(&self) -> &[BasicValueEnum<'ctx>] {
        match &self.exit_arg {
            Some(arg) => slice::from_ref(arg),
            None => &[],
        }
    }

    fn build_terminate_call_before(&self, original: InstructionValue<'ctx>) -> CallSiteValue<'ctx> {
        if self.has_expected_ty
            && matches!(
                original.get_opcode(),
                InstructionOpcode::Call | InstructionOpcode::Invoke
            )
        {
            // SAFETY: `original` 是块内合法的 Call/Invoke 指令
            unsafe { original.build_call_preserving_bundles(self.callee_fn, self.basic_args(), "") }
        } else {
            // SAFETY: 显式指定函数类型以兼容签名不一致的已有函数声明以及 `CallBr`
            unsafe { self.build_call_with_explicit_type(original) }
        }
    }

    unsafe fn build_call_with_explicit_type(
        &self,
        original: InstructionValue<'ctx>,
    ) -> CallSiteValue<'ctx> {
        unsafe {
            let original_ref = original.as_value_ref();
            let callee_ref = self.callee_fn.as_value_ref();
            let builder = LLVMCreateBuilderInContext(self.raw_ctx);
            LLVMPositionBuilderBefore(builder, original_ref);

            let bundle_count = LLVMGetNumOperandBundles(original_ref);
            let mut bundles: Vec<LLVMOperandBundleRef> = Vec::with_capacity(bundle_count as usize);
            for index in 0..bundle_count {
                bundles.push(LLVMGetOperandBundleAtIndex(original_ref, index));
            }

            let mut raw_arg_opt = self.exit_arg.map(|arg| arg.as_value_ref());
            let (args_ptr, args_len) = match &mut raw_arg_opt {
                Some(arg_ref) => (ptr::from_mut(arg_ref), 1),
                None => (ptr::null_mut(), 0),
            };

            let bundles_ptr = if bundles.is_empty() {
                ptr::null_mut()
            } else {
                bundles.as_mut_ptr()
            };

            let call_value = LLVMBuildCallWithOperandBundles(
                builder,
                self.callee_ty.as_type_ref(),
                callee_ref,
                args_ptr,
                args_len,
                bundles_ptr,
                bundle_count,
                c"".as_ptr(),
            );

            for bundle in bundles {
                LLVMDisposeOperandBundle(bundle);
            }
            LLVMDisposeBuilder(builder);
            LLVMSetInstructionCallConv(call_value, LLVMGetFunctionCallConv(callee_ref));
            CallSiteValue::new(call_value)
        }
    }

    fn build_terminate_call_at_end(&self, builder: &Builder<'ctx>) -> CallSiteValue<'ctx> {
        let meta_arg: Option<BasicMetadataValueEnum<'ctx>> = self.exit_arg.map(Into::into);
        let args: &[BasicMetadataValueEnum<'ctx>] = match &meta_arg {
            Some(arg) => slice::from_ref(arg),
            None => &[],
        };

        if self.has_expected_ty {
            builder
                .build_direct_call(self.callee_fn, args, "")
                .expect("build direct terminate call")
        } else {
            builder
                .build_indirect_call(
                    self.callee_ty,
                    self.callee_fn.as_global_value().as_pointer_value(),
                    args,
                    "",
                )
                .expect("build indirect terminate call")
        }
    }
}

#[inline]
fn find_direct_call_site(target: FunctionValue) -> Option<InstructionValue> {
    let target_ref = target.as_value_ref();
    let mut use_ = target.get_first_use();
    while let Some(value_use) = use_ {
        let next_use = value_use.get_next_use();
        if let Some(instruction) = value_use.get_user().as_instruction_value()
            && matches!(
                instruction.get_opcode(),
                InstructionOpcode::Call | InstructionOpcode::Invoke | InstructionOpcode::CallBr
            )
            && unsafe { LLVMGetCalledValue(instruction.as_value_ref()) == target_ref }
        {
            return Some(instruction);
        }
        use_ = next_use;
    }
    None
}

#[inline]
fn neutralize_call_site<'ctx>(terminator: &Terminator<'ctx>, instruction: InstructionValue<'ctx>) {
    let term_call = terminator.build_terminate_call_before(instruction);
    term_call.add_attribute(AttributeLoc::Function, terminator.noreturn_attr);
    unsafe {
        instruction.change_to_unreachable();
    }
}

fn gut_function<'ctx>(
    terminator: &Terminator<'ctx>,
    builder: &Builder<'ctx>,
    function: FunctionValue<'ctx>,
) {
    unsafe {
        function.delete_body();
    }
    let entry = terminator.ctx.append_basic_block(function, "entry");
    builder.position_at_end(entry);
    let term_call = terminator.build_terminate_call_at_end(builder);
    term_call.add_attribute(AttributeLoc::Function, terminator.noreturn_attr);
    builder
        .build_unreachable()
        .expect("build unreachable after terminate call");
    function.add_attribute(AttributeLoc::Function, terminator.noreturn_attr);
    function.clear_comdat();
    function.set_dso_local(true);
    let global = function.as_global_value();
    global.set_linkage(Linkage::Internal);
    global.set_visibility(GlobalVisibility::Default);
    global.set_dll_storage_class(DLLStorageClass::Default);
}

pub struct RustRemovePanicPass;

impl ModulePass for RustRemovePanicPass {
    fn name(&self) -> &str {
        "RustRemovePanic"
    }

    fn run(&mut self, module: &mut ModuleRef<'_>) -> PreservedAnalyses {
        let tag = self.name();
        let cfg = &CONFIG.rust_remove_panic;
        if !cfg.enabled {
            pdebug!(tag, module, "Pass 已在配置中禁用，跳过。");
            return PreservedAnalyses::All;
        }

        let inkwell_module = module.as_inkwell();
        let m = &*inkwell_module;
        let ctx = m.get_context();
        let mut demangle_buf = String::with_capacity(256);

        let targets: Vec<FunctionValue<'_>> = m
            .get_functions()
            .filter(|&f| {
                !(f.as_global_value().is_declaration() && f.get_first_use().is_none())
                    && is_panic_related(f, &mut demangle_buf)
            })
            .collect();

        if targets.is_empty() {
            return PreservedAnalyses::All;
        }

        pdebug!(
            tag,
            module,
            "发现 {} 个 rust panic 相关函数 (mode: {:?})",
            targets.len(),
            cfg.mode
        );

        let terminator = Terminator::new(m, ctx);
        let builder = ctx.create_builder();

        // 第一阶段：先统一掏空所有目标函数的函数体
        let mut gutted_funcs = 0usize;
        for &function in &targets {
            if !function.as_global_value().is_declaration() {
                gut_function(&terminator, &builder, function);
                gutted_funcs += 1;
            }
        }

        // 第二阶段：阻断剩余所有来自业务代码的直接调用点
        let mut replaced_calls = 0usize;
        for &function in &targets {
            while let Some(instruction) = find_direct_call_site(function) {
                neutralize_call_site(&terminator, instruction);
                replaced_calls += 1;
            }
        }

        if gutted_funcs == 0 && replaced_calls == 0 {
            return PreservedAnalyses::All;
        }

        pdebug!(
            tag,
            module,
            "成功清空 {} 个 panic 函数实现，并阻断了 {} 处 panic 调用。",
            gutted_funcs,
            replaced_calls
        );
        PreservedAnalyses::None
    }
}

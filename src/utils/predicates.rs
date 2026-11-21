#![allow(unused)]

use llvm_pass::inkwell::builder::Builder;
use llvm_pass::inkwell::context::ContextRef;
use llvm_pass::inkwell::types::IntType;
use llvm_pass::inkwell::values::{BasicValue, GlobalValue, IntValue};
use llvm_pass::inkwell::IntPredicate;

use lib_unknown::rand::core::{random, };

#[derive(Debug, Clone, Copy)]
pub enum OpaquePredicateKind {
    /// (奇数)^2 mod 8 == 1
    OddSquareMod8Eq1,
    /// x^2 mod 4 ∈ {0, 1}
    SquareMod4Le1,
    /// x^2 + y^2 mod 4 != 3
    SumTwoSquaresMod4Ne3,
    /// x * (x + 1) 为偶数
    ConsecutiveProductEven,
    /// ((x >> 1) << 1) <= x（无符号）
    ShiftMaskLessEqual,
    /// ~x == -x - 1
    MbaNotNeg,
    /// (x | y) - (x & y) == x ^ y
    MbaOrAndXor,
    /// x + y == (x & y) + (x | y)
    MbaAndOrAdd,
    /// n * (n + 1) * (n + 2) 能被 6 整除
    Product3ConsecutiveDiv6,
}

pub const ALL_PREDICATES: [OpaquePredicateKind; 9] = [
    OpaquePredicateKind::OddSquareMod8Eq1,
    OpaquePredicateKind::SquareMod4Le1,
    OpaquePredicateKind::SumTwoSquaresMod4Ne3,
    OpaquePredicateKind::ConsecutiveProductEven,
    OpaquePredicateKind::ShiftMaskLessEqual,
    OpaquePredicateKind::MbaNotNeg,
    OpaquePredicateKind::MbaOrAndXor,
    OpaquePredicateKind::MbaAndOrAdd,
    OpaquePredicateKind::Product3ConsecutiveDiv6,
];

#[inline]
fn i32_const(ctx: ContextRef<'_>, value: u64) -> IntValue<'_> {
    ctx.i32_type().const_int(value, false)
}

#[inline]
fn random_i32(ctx: ContextRef<'_>) -> IntValue<'_> {
    i32_const(ctx, random::<u32>() as u64)
}

/// 从 noise 全局变量做一次 volatile 读取。
pub fn load_noise<'ctx>(
    builder: &Builder<'ctx>,
    i32_ty: IntType<'ctx>,
    noise_gv: GlobalValue<'ctx>,
) -> Option<IntValue<'ctx>> {
    let value = builder
        .build_load(i32_ty, noise_gv.as_pointer_value(), "bbs.noise")
        .ok()?;

    if let Some(inst) = value.as_instruction_value() {
        let _ = inst.set_volatile(true);
        let _ = inst.set_alignment(4);
    }

    Some(value.into_int_value())
}

/// 构造一个恒为真的不透明谓词。
pub fn build_opaque_true_predicate<'ctx>(
    builder: &Builder<'ctx>,
    ctx: ContextRef<'ctx>,
    noise_gv: GlobalValue<'ctx>,
    kind: OpaquePredicateKind,
) -> Option<IntValue<'ctx>> {
    let noise = load_noise(builder, ctx.i32_type(), noise_gv)?;
    let x = builder
        .build_xor(noise, random_i32(ctx), "bbs.x")
        .ok()?;

    Some(match kind {
        OpaquePredicateKind::OddSquareMod8Eq1 => {
            let odd = builder.build_or(x, i32_const(ctx, 1), "bbs.odd").ok()?;
            let square = builder
                .build_int_mul(odd, odd, "bbs.sq")
                .ok()?;
            let masked = builder
                .build_and(square, i32_const(ctx, 7), "bbs.m8")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::EQ, masked, i32_const(ctx, 1), "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::SquareMod4Le1 => {
            let square = builder.build_int_mul(x, x, "bbs.sq").ok()?;
            let masked = builder
                .build_and(square, i32_const(ctx, 3), "bbs.m4")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::ULT, masked, i32_const(ctx, 2), "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::SumTwoSquaresMod4Ne3 => {
            let y = builder
                .build_xor(x, random_i32(ctx), "bbs.y")
                .ok()?;
            let sqx = builder.build_int_mul(x, x, "bbs.sqx").ok()?;
            let sqy = builder.build_int_mul(y, y, "bbs.sqy").ok()?;
            let sum = builder.build_int_add(sqx, sqy, "bbs.sum").ok()?;
            let masked = builder
                .build_and(sum, i32_const(ctx, 3), "bbs.m4")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::NE, masked, i32_const(ctx, 3), "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::ConsecutiveProductEven => {
            let xp1 = builder
                .build_int_add(x, i32_const(ctx, 1), "bbs.xp1")
                .ok()?;
            let product = builder.build_int_mul(x, xp1, "bbs.prod").ok()?;
            let bit = builder
                .build_and(product, i32_const(ctx, 1), "bbs.bit")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::EQ, bit, i32_const(ctx, 0), "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::ShiftMaskLessEqual => {
            let one = i32_const(ctx, 1);
            let shr = builder
                .build_right_shift(x, one, false, "bbs.shr")
                .ok()?;
            let shl = builder.build_left_shift(shr, one, "bbs.shl").ok()?;
            builder
                .build_int_compare(IntPredicate::ULE, shl, x, "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::MbaNotNeg => {
            let not_x = builder.build_not(x, "bbs.not").ok()?;
            let neg_x = builder.build_int_neg(x, "bbs.neg").ok()?;
            let rhs = builder
                .build_int_sub(neg_x, i32_const(ctx, 1), "bbs.rhs")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::EQ, not_x, rhs, "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::MbaOrAndXor => {
            let y = builder
                .build_xor(x, random_i32(ctx), "bbs.y")
                .ok()?;
            let or_xy = builder.build_or(x, y, "bbs.or").ok()?;
            let and_xy = builder.build_and(x, y, "bbs.and").ok()?;
            let lhs = builder
                .build_int_sub(or_xy, and_xy, "bbs.lhs")
                .ok()?;
            let rhs = builder.build_xor(x, y, "bbs.rhs").ok()?;
            builder
                .build_int_compare(IntPredicate::EQ, lhs, rhs, "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::MbaAndOrAdd => {
            let y = builder
                .build_xor(x, random_i32(ctx), "bbs.y")
                .ok()?;
            let and_xy = builder.build_and(x, y, "bbs.and").ok()?;
            let or_xy = builder.build_or(x, y, "bbs.or").ok()?;
            let lhs = builder.build_int_add(x, y, "bbs.lhs").ok()?;
            let rhs = builder
                .build_int_add(and_xy, or_xy, "bbs.rhs")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::EQ, lhs, rhs, "bbs.pred")
                .ok()?
        }
        OpaquePredicateKind::Product3ConsecutiveDiv6 => {
            let n = builder
                .build_int_unsigned_rem(x, i32_const(ctx, 1000), "bbs.n")
                .ok()?;
            let np1 = builder
                .build_int_add(n, i32_const(ctx, 1), "bbs.np1")
                .ok()?;
            let np2 = builder
                .build_int_add(n, i32_const(ctx, 2), "bbs.np2")
                .ok()?;
            let mul1 = builder.build_int_mul(n, np1, "bbs.m1").ok()?;
            let mul2 = builder.build_int_mul(mul1, np2, "bbs.m2").ok()?;
            let rem = builder
                .build_int_unsigned_rem(mul2, i32_const(ctx, 6), "bbs.rem")
                .ok()?;
            builder
                .build_int_compare(IntPredicate::EQ, rem, i32_const(ctx, 0), "bbs.pred.div6")
                .ok()?
        }
    })
}

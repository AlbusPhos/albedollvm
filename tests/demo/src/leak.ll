; ModuleID = 'leak.ll'
source_filename = "leak.ll"

@rustc_path = private unnamed_addr constant [74 x i8] c"/rustc/3659db0d3e2cd634c766fcda79ed118eca31a3fd/library/core/src/panic.rs\00", align 1
@src_path = private unnamed_addr constant [19 x i8] c"src/utils/helper.rs", align 1
@secret_key = private unnamed_addr constant [32 x i8] c"Bearer sk-live-0123456789abcdef\00", align 1
@safe_str = private unnamed_addr constant [12 x i8] c"hello world\00", align 1
@zero_buf = internal unnamed_addr constant [64 x i8] zeroinitializer, align 1
@undef_buf = internal unnamed_addr constant [64 x i8] undef, align 1

define ptr @keep_alive() {
entry:
  ret ptr @safe_str
}
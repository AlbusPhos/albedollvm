; ModuleID = 'bytes.ll'
source_filename = "bytes.ll"

; 1. 命中 substrings + regex 规则 (level = 3)，仅被指令引用 -> 应被替换并彻底删除
@secret_key = private unnamed_addr constant [29 x i8] c"sk-live-0123456789abcdef1234\00", align 1

; 2. 命中 subbytesb64 规则 ("Bearer " -> "QmVhcmVyIA==", level = 2)，在 PHI 节点中被引用 -> 应被替换并彻底删除
@phi_secret_a = private unnamed_addr constant [25 x i8] c"Bearer phi-branch-alpha!\00", align 1
@phi_secret_b = private unnamed_addr constant [25 x i8] c"Bearer phi-branch-bravo!\00", align 1

; 3. 命中排除规则 (exclude = true, "sk-live-00") -> 应跳过不混淆
@excluded_key = private unnamed_addr constant [29 x i8] c"sk-live-0023456789abcdef1234\00", align 1

; 4. 同时被全局常量表 (@global_table) 和指令引用的敏感常量 -> 指令引用被替换，但原符号需保留
@shared_secret = private unnamed_addr constant [29 x i8] c"sk-test-abcdef0123456789abcd\00", align 1
@global_table = internal unnamed_addr constant [1 x ptr] [ptr @shared_secret], align 8

; 5. 非常量 Global (global 而非 constant) 与普通短字符串
@mutable_buf = private unnamed_addr global [29 x i8] c"sk-live-mutable-0123456789ab\00", align 1
@safe_str = private unnamed_addr constant [12 x i8] c"hello world\00", align 1

declare void @consume_pair(ptr, ptr)

define ptr @get_secret() {
entry:
  ret ptr @secret_key
}

define void @use_duplicate_operands() {
entry:
  call void @consume_pair(ptr @secret_key, ptr @secret_key)
  ret void
}

define ptr @select_phi_secret(i1 %cond) {
entry:
  br i1 %cond, label %left_bb, label %right_bb

left_bb:
  br label %merge_bb

right_bb:
  br label %merge_bb

merge_bb:
  %res = phi ptr [ @phi_secret_a, %left_bb ], [ @phi_secret_b, %right_bb ]
  ret ptr %res
}

define ptr @get_shared_secret() {
entry:
  ret ptr @shared_secret
}

define ptr @keep_others() {
entry:
  call void @consume_pair(ptr @mutable_buf, ptr @safe_str)
  ret ptr @excluded_key
}

define ptr @keep_table() {
entry:
  ret ptr @global_table
}
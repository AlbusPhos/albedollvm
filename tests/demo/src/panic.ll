; ModuleID = 'panic.ll'
source_filename = "panic.ll"

$panic_comdat = comdat any

declare void @_ZN4core9panicking9panic_fmt17h1234567890abcdefE()

define void @_ZN4core9panicking18panic_bounds_check17h1234567890abcdefE(i64 %index, i64 %len) comdat($panic_comdat) {
entry:
  call void @_ZN4core9panicking9panic_fmt17h1234567890abcdefE()
  unreachable
}

define i32 @caller(i32 %x) {
entry:
  %cmp = icmp slt i32 %x, 0
  br i1 %cmp, label %panic_bb, label %ok_bb

panic_bb:
  %dead_prep = add i32 %x, 9999
  call void @_ZN4core9panicking18panic_bounds_check17h1234567890abcdefE(i64 1, i64 0) [ "deopt"(i32 %dead_prep) ]
  ret i32 -1

ok_bb:
  ret i32 %x
}
// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;

/// Panic 替换模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PanicMode {
    /// 调用 C 标准库 `void @exit(i32)`
    #[default]
    Exit,
    /// 调用 LLVM 内建函数 `void @llvm.trap()`（x86 下为 `ud2`，ARM64 下为 `brk`）
    Trap,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RustRemovePanicConfig {
    pub enabled: bool,
    pub mode: PanicMode,
    pub exit_code: i32,
}

impl Default for RustRemovePanicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: PanicMode::Exit,
            exit_code: 101,
        }
    }
}

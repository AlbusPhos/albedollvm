// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// src/lib.rs
#![allow(unused)]

mod all_pass;
mod utils;

use crate::all_pass::{bytes_obfuscation, remove_leak, rust_remove_panic};
use llvm_pass::*;

export_llvm_plugin! {
    register: |pb: &mut PassBuilder| {
        utils::logger::init_logger();
        pb.register_module_pipeline_parsing_callback(|name, mpm| match name {
            "remove_leak" | "rl" => {
                mpm.add_pass(remove_leak::RemoveLeakPass);
                true
            }
            "rust_remove_panic" | "rp" => {
                mpm.add_pass(rust_remove_panic::RustRemovePanicPass);
                // mpm.add_simplify_cfg();
                mpm.add_adce();
                mpm.add_global_dce();
                true
            }
            "bytes_obfuscation" | "bo" => {
                mpm.add_pass(bytes_obfuscation::BytesObfuscationPass);
                true
            }
            _ => false,
        });
    }
}

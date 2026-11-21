extern crate core;

mod all_pass;
mod utils;

use crate::all_pass::{remove_leak, rust_remove_panic};
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
            _ => false,
        });

    }
}

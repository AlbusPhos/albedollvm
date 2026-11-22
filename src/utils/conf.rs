// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// src/utils/conf.rs
pub mod func;
pub mod remove_leak;
pub mod rust_remove_panic;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use crate::{pdebug, pinfo, pwarn};
use serde::Deserialize;

const TAG: &str = "OLLVM_CONFIG";
const CONFIG_PATH_ENV: &str = "OLLVM_CONFIG";
const DEFAULT_CONFIG_FILE: &str = "ollvm.toml";

/// 全局唯一配置实例，整个编译期仅读取、合并和解析一次
pub static CONFIG: LazyLock<OllvmConfig> = LazyLock::new(OllvmConfig::load);

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct OllvmConfig {
    pub rust_remove_panic: rust_remove_panic::RustRemovePanicConfig,
    pub remove_leak: remove_leak::RemoveLeakConfig,
    pub target_func: func::TargetFuncConfig,
}

impl OllvmConfig {
    fn load() -> Self {
        let mut cfg = Self::load_raw();
        cfg.remove_leak.finalize();
        cfg.target_func.finalize();
        cfg
    }

    fn load_raw() -> Self {
        let (path, is_explicit) = Self::resolve_path();

        if !path.exists() {
            if is_explicit {
                pwarn!(
                    TAG,
                    "环境变量 {} 指定的配置文件不存在: {}，将使用默认配置。",
                    CONFIG_PATH_ENV,
                    path.display()
                );
            } else {
                pdebug!(TAG, "未检测到 {}，使用内置默认配置。", path.display());
            }
            return Self::default();
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                pwarn!(
                    TAG,
                    "无法读取配置文件 {}: {}，将使用默认配置。",
                    path.display(),
                    err
                );
                return Self::default();
            }
        };

        match toml::from_str::<Self>(&content) {
            Ok(cfg) => {
                pinfo!(TAG, "已加载配置文件: {}", path.display());
                cfg
            }
            Err(err) => {
                pwarn!(
                    TAG,
                    "配置文件 {} 解析失败: {}，将使用默认配置。",
                    path.display(),
                    err
                );
                Self::default()
            }
        }
    }

    /// 返回 (配置文件路径, 是否由环境变量显式指定)
    fn resolve_path() -> (PathBuf, bool) {
        if let Some(env_path) = env::var_os(CONFIG_PATH_ENV)
            && !env_path.is_empty()
        {
            return (PathBuf::from(env_path), true);
        }
        (Path::new(DEFAULT_CONFIG_FILE).to_path_buf(), false)
    }
}

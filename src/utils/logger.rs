// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// src/utils/logger.rs
use core::fmt;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::env;
use std::io::{self, IsTerminal, Write};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

static LOGGER: Logger = Logger;
static INIT: Once = Once::new();

static COLOR_STDOUT: AtomicBool = AtomicBool::new(false);
static COLOR_STDERR: AtomicBool = AtomicBool::new(false);

struct Logger;

impl Log for Logger {
    #[inline]
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let is_err = record.level() == Level::Error;
        let use_color = if is_err {
            COLOR_STDERR.load(Ordering::Relaxed)
        } else {
            COLOR_STDOUT.load(Ordering::Relaxed)
        };

        let prefix = match (record.level(), use_color) {
            (Level::Error, true) => "\x1b[1;31m[x]\x1b[0m", // RED + BOLD
            (Level::Error, false) => "[x]",
            (Level::Warn, true) => "\x1b[1;33m[!]\x1b[0m", // YELLOW + BOLD
            (Level::Warn, false) => "[!]",
            (Level::Info, true) => "\x1b[1;32m[*]\x1b[0m", // GREEN + BOLD
            (Level::Info, false) => "[*]",
            (Level::Debug | Level::Trace, true) => "\x1b[1;90m[-]\x1b[0m", // GRAY + BOLD
            (Level::Debug | Level::Trace, false) => "[-]",
        };

        if is_err {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "{} {}", prefix, record.args());
        } else {
            let mut stdout = io::stdout().lock();
            let _ = writeln!(stdout, "{} {}", prefix, record.args());
        }
    }

    fn flush(&self) {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
    }
}

fn resolve_log_level() -> LevelFilter {
    match env::var("OLLVM_LOG_LEVEL") {
        Ok(value) => {
            let s = value.trim();
            if s.eq_ignore_ascii_case("TRACE") {
                LevelFilter::Trace
            } else if s.eq_ignore_ascii_case("DEBUG") {
                LevelFilter::Debug
            } else if s.eq_ignore_ascii_case("INFO") {
                LevelFilter::Info
            } else if s.eq_ignore_ascii_case("WARN") {
                LevelFilter::Warn
            } else if s.eq_ignore_ascii_case("ERROR") {
                LevelFilter::Error
            } else if s.eq_ignore_ascii_case("NONE") || s.eq_ignore_ascii_case("OFF") {
                LevelFilter::Off
            } else {
                LevelFilter::Warn
            }
        }
        Err(_) => LevelFilter::Warn,
    }
}

fn resolve_color_setting() -> (bool, bool) {
    if let Ok(val) = env::var("OLLVM_LOG_COLOR") {
        let s = val.trim();
        if s.eq_ignore_ascii_case("always")
            || s.eq_ignore_ascii_case("force")
            || s.eq_ignore_ascii_case("true")
            || s == "1"
        {
            return (true, true);
        }
        if s.eq_ignore_ascii_case("never")
            || s.eq_ignore_ascii_case("none")
            || s.eq_ignore_ascii_case("false")
            || s == "0"
        {
            return (false, false);
        }
    }

    if env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return (false, false);
    }

    (io::stdout().is_terminal(), io::stderr().is_terminal())
}

pub fn init_logger() {
    INIT.call_once(|| {
        let (color_out, color_err) = resolve_color_setting();
        COLOR_STDOUT.store(color_out, Ordering::Relaxed);
        COLOR_STDERR.store(color_err, Ordering::Relaxed);

        let level = resolve_log_level();
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(level);
    });
}

#[inline(always)]
pub fn is_log_enabled(level: Level) -> bool {
    level <= log::STATIC_MAX_LEVEL && level <= log::max_level()
}

pub struct Bracket<'a>(pub &'a str);

impl fmt::Display for Bracket<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let clean = self.0.trim_start_matches('[').trim_end_matches(']');
        write!(f, "[{}]", clean)
    }
}

pub struct Short<'a>(pub &'a str);

impl fmt::Display for Short<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_LEN: usize = 20;

        let clean = self.0.trim_start_matches('[').trim_end_matches(']');
        let base = clean.rsplit(['/', '\\']).next().unwrap_or(clean);

        if base.len() <= MAX_LEN || MAX_LEN < 5 {
            return write!(f, "[{}]", base);
        }

        let avail = MAX_LEN - 2;
        let head_target = avail / 2;
        let tail_target = avail - head_target;

        let mut head_end = head_target;
        while !base.is_char_boundary(head_end) {
            head_end -= 1;
        }

        let mut tail_start = base.len() - tail_target;
        while !base.is_char_boundary(tail_start) {
            tail_start += 1;
        }

        if head_end >= tail_start {
            write!(f, "[{}]", base)
        } else {
            write!(f, "[{}..{}]", &base[..head_end], &base[tail_start..])
        }
    }
}

macro_rules! log {
    // 形式 1：纯消息 -> `[*] msg`
    ($level:expr, $fmt:literal $(, $($arg:tt)+)?) => {{
        let lvl: ::log::Level = $level;
        if $crate::utils::logger::is_log_enabled(lvl) {
            ::log::log!(lvl, $fmt $(, $($arg)+)?);
        }
    }};

    // 形式 2：带 TAG -> `[*] [TAG] msg`
    ($level:expr, $tag:expr, $fmt:literal $(, $($arg:tt)+)?) => {{
        let lvl: ::log::Level = $level;
        if $crate::utils::logger::is_log_enabled(lvl) {
            ::log::log!(
                lvl,
                ::core::concat!("{} ", $fmt),
                $crate::utils::logger::Bracket($tag)
                $(, $($arg)+)?
            );
        }
    }};

    // 形式 3：带 TAG 与 单个上下文(module 或 func) -> `[*] [TAG] [mod..le] msg`
    ($level:expr, $tag:expr, $ctx:expr, $fmt:literal $(, $($arg:tt)+)?) => {{
        let lvl: ::log::Level = $level;
        if $crate::utils::logger::is_log_enabled(lvl) {
            ::log::log!(
                lvl,
                ::core::concat!("{} {} ", $fmt),
                $crate::utils::logger::Bracket($tag),
                $crate::utils::logger::Short(&$ctx.name())
                $(, $($arg)+)?
            );
        }
    }};
}
pub use log;

#[macro_export]
macro_rules! perror {
    ($($tt:tt)+) => { $crate::utils::logger::log!(::log::Level::Error, $($tt)+) };
}
#[macro_export]
macro_rules! pwarn {
    ($($tt:tt)+) => { $crate::utils::logger::log!(::log::Level::Warn, $($tt)+) };
}
#[macro_export]
macro_rules! pinfo {
    ($($tt:tt)+) => { $crate::utils::logger::log!(::log::Level::Info, $($tt)+) };
}
#[macro_export]
macro_rules! pdebug {
    ($($tt:tt)+) => { $crate::utils::logger::log!(::log::Level::Debug, $($tt)+) };
}
#[macro_export]
macro_rules! ptrace {
    ($($tt:tt)+) => { $crate::utils::logger::log!(::log::Level::Trace, $($tt)+) };
}

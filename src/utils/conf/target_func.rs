// SPDX-License-Identifier: MPL-2.0
//
// Copyright (c) 2026 AlbusPhos <owo.zzz@proton.me>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// src/utils/conf/func.rs
// 用于 llvm 树外插件的函数名匹配与 Pass 目标函数选择决策

use std::cell::OnceCell;
use std::sync::LazyLock;

use dashmap::DashMap;
use lib_unknown::rand::core::random_range;
use memchr::{memchr, memchr2, memmem, memrchr};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Deserializer};
use symbolic_demangle::Demangle;

use super::TAG;
use crate::{pdebug, pwarn};

const MAX_PATH_SEGMENTS: usize = 64;

/// 全局符号 Demangle 与路径切分缓存
static SYM_CACHE: LazyLock<DashMap<Box<str>, &'static ParsedSym, FxBuildHasher>> =
    LazyLock::new(|| DashMap::with_capacity_and_hasher(256, FxBuildHasher));

/// 支持在 TOML 中既可以写数组 `["a", "b"]` 也可以写单个字符串 `"a"`
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        Vec(Vec<String>),
        Single(String),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::Vec(v) => Ok(v),
        StringOrVec::Single(s) => Ok(vec![s]),
    }
}

/// 符号编码体系分类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymAbi {
    Msvc,
    Itanium,
    Swift,
    Other,
}

impl SymAbi {
    #[inline]
    fn detect(raw_name: &str) -> Self {
        let bytes = raw_name.as_bytes();
        if bytes.starts_with(b"?") {
            Self::Msvc
        } else if bytes.starts_with(b"_R") || bytes.starts_with(b"__R") {
            Self::Other
        } else if bytes.starts_with(b"_$s") || bytes.starts_with(b"$s") {
            Self::Swift
        } else if bytes.starts_with(b"_Z")
            || bytes.starts_with(b"__Z")
            || memmem::find(bytes, b"_Z").is_some()
        {
            Self::Itanium
        } else {
            Self::Other
        }
    }
}

/// `[target_func]` 顶层配置
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TargetFuncConfig {
    /// 显式函数匹配规则列表：`[[target_func.rule]]`
    #[serde(default)]
    #[serde(alias = "rule")]
    pub rules: Vec<TargetFuncRule>,
    /// 各 Pass 的补充概率配置：`[target_func.<pass_name>]`
    #[serde(flatten, default)]
    pub passes: FxHashMap<String, PassTargetConfig>,
}

impl Default for TargetFuncConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            passes: FxHashMap::default(),
        }
    }
}

/// `[target_func.<pass_name>]` 单 Pass 补充配置
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(default)]
pub struct PassTargetConfig {
    /// 对未明确选择的其他函数，按该百分比概率 (0..=100) 启用此 Pass
    pub other_pct: u8,
}

impl TargetFuncConfig {
    pub(super) fn finalize(&mut self) {
        self.rules.retain_mut(|rule| {
            if rule.func.as_deref().is_some_and(|f| f.trim().is_empty()) {
                rule.func = None;
            }
            rule.passes.retain(|p| !p.trim().is_empty());

            if rule.is_empty() {
                pwarn!(
                    TAG,
                    "[[target_func.rules]] 存在 func 与 path 均为空的无效规则，已忽略。"
                );
                return false;
            }
            true
        });

        for (pass_name, pass_cfg) in &mut self.passes {
            if pass_cfg.other_pct > 100 {
                pwarn!(
                    TAG,
                    "[target_func.{}] other_pct = {} 超出 0..=100 范围，已截断为 100。",
                    pass_name,
                    pass_cfg.other_pct
                );
                pass_cfg.other_pct = 100;
            }
        }
    }

    /// 获取指定 Pass 配置的 `other_pct`
    #[inline]
    pub fn other_pct(&self, pass_name: &str) -> u8 {
        self.passes
            .get(pass_name)
            .map_or(0, |cfg| cfg.other_pct.min(100))
    }

    /// 判断指定函数 `raw_name` 是否应当运行 `pass_name`
    #[inline]
    pub fn should_run(&self, raw_name: &str, pass_name: &str) -> bool {
        if raw_name.is_empty() || pass_name.is_empty() {
            return false;
        }
        let sym = FuncSymbol::new(raw_name);
        self.should_run_symbol(&sym, pass_name)
    }

    /// 核心决策入口
    pub fn should_run_symbol(&self, sym: &FuncSymbol<'_>, pass_name: &str) -> bool {
        let raw = sym.raw_name();
        if raw.is_empty() || pass_name.is_empty() {
            return false;
        }

        let mut matched_include_idx: Option<usize> = None;

        for (idx, rule) in self.rules.iter().enumerate() {
            if !rule.applies_to_pass(pass_name) {
                continue;
            }
            if rule.exclude {
                if rule.matches_symbol(sym) {
                    pdebug!(
                        TAG,
                        "[{}] 函数 {} 命中排除规则 #{}，跳过。",
                        pass_name,
                        raw,
                        idx
                    );
                    return false;
                }
            } else if matched_include_idx.is_none() && rule.matches_symbol(sym) {
                matched_include_idx = Some(idx);
            }
        }

        if let Some(idx) = matched_include_idx {
            pdebug!(
                TAG,
                "[{}] 函数 {} 命中启用规则 #{}，执行。",
                pass_name,
                raw,
                idx
            );
            return true;
        }

        let pct = self.other_pct(pass_name);
        if pct == 0 {
            return false;
        }

        for (idx, rule) in self.rules.iter().enumerate() {
            if !rule.exclude && !rule.applies_to_pass(pass_name) && rule.matches_symbol(sym) {
                pdebug!(
                    TAG,
                    "[{}] 函数 {} 已被规则 #{} 指定给其他 Pass，跳过概率抽样。",
                    pass_name,
                    raw,
                    idx
                );
                return false;
            }
        }

        if random_range(1..=100u8) <= pct {
            pdebug!(
                TAG,
                "[{}] 函数 {} 命中 other_pct ({}%) 概率抽样，执行。",
                pass_name,
                raw,
                pct
            );
            true
        } else {
            false
        }
    }
}

/// 函数匹配规则：`[[target_func.rules]]`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TargetFuncRule {
    /// 可选：目标函数名（单一标识符，如 `"begin_panic"` 或 `"closure"`）
    /// 若不填，则默认匹配 `path` 下的所有函数
    pub func: Option<String>,
    /// 可选：模块/命名空间/类型路径序列（必须是已预先拆分的独立标识符列表）
    /// 例如: `["std", "panicking"]` 或 `["my_crate", "crypto"]` 或 `["github_com", "org", "pkg"]`
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub path: Vec<String>,
    /// 可选：对该函数应用的 Pass 列表；为空表示应用全部 Pass
    #[serde(
        default,
        alias = "pass",
        deserialize_with = "deserialize_string_or_vec"
    )]
    pub passes: Vec<String>,
    /// 控制是排除 (`true`) 还是启用 (`false`，默认)
    pub exclude: bool,
}

impl TargetFuncRule {
    /// 判断该规则是否对指定的 `pass_name` 生效
    #[inline]
    pub fn applies_to_pass(&self, pass_name: &str) -> bool {
        self.passes.is_empty() || self.passes.iter().any(|p| p == pass_name)
    }

    /// 判断规则是否为空（既未指定有效 `func`，也未指定有效 `path`）
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.func.as_ref().is_none_or(|f| f.is_empty())
            && Self::path_segments(&self.path).next().is_none()
    }

    /// 直接迭代预先切分好的路径段，过滤语法关键字与空段
    #[inline]
    fn path_segments(path: &[String]) -> impl DoubleEndedIterator<Item = &str> {
        path.iter()
            .map(String::as_str)
            .filter(|s| !s.is_empty() && !ParsedSym::is_ignored_keyword(s))
    }

    /// 单规则快速匹配入口（仅判断符号是否匹配 `func` 与 `path`，不考虑 `exclude` 与 `pass`）
    #[inline]
    pub fn matches(&self, raw_name: &str) -> bool {
        if self.is_empty() || raw_name.is_empty() {
            return false;
        }
        let sym = FuncSymbol::new(raw_name);
        self.matches_symbol(&sym)
    }

    /// 多规则场景下的高效匹配入口
    #[inline]
    pub fn matches_symbol(&self, sym: &FuncSymbol<'_>) -> bool {
        if self.is_empty() || !self.may_match_raw(sym.cleaned_raw(), sym.abi) {
            return false;
        }
        self.matches_parsed(sym.parsed())
    }

    /// 批量规则匹配辅助函数：只要命中 `rules` 中的任意一条即返回 `true`
    #[inline]
    pub fn matches_any(rules: &[Self], raw_name: &str) -> bool {
        if rules.is_empty() || raw_name.is_empty() {
            return false;
        }
        let sym = FuncSymbol::new(raw_name);
        rules.iter().any(|rule| rule.matches_symbol(&sym))
    }

    /// 【第一阶段：未解修饰状态机预筛】单趟游标扫描 + 标识符左边界校验
    ///
    /// - 正向编码体系（Rust `_R`/`_ZN`、C++ Itanium `_Z`、Swift `_$s`、Go、C）：
    ///   按 `path[0] -> path[1] -> ... -> func` 顺序单向推进游标。
    /// - 逆向编码体系（C++ MSVC `?func@inner@outer@@`）：
    ///   按 `func -> path.rev()` 顺序单向推进游标。
    #[inline]
    fn may_match_raw(&self, raw_name: &str, abi: SymAbi) -> bool {
        if raw_name.is_empty() {
            return false;
        }
        let mut cursor = 0usize;
        let mut prev_token = "";

        if abi == SymAbi::Msvc {
            if let Some(func) = &self.func
                && !func.is_empty()
                && !Self::advance_raw_token(
                    raw_name,
                    &mut cursor,
                    &mut prev_token,
                    func,
                    SymAbi::Msvc,
                )
            {
                return false;
            }
            for seg in Self::path_segments(&self.path).rev() {
                if !Self::advance_raw_token(
                    raw_name,
                    &mut cursor,
                    &mut prev_token,
                    seg,
                    SymAbi::Msvc,
                ) {
                    return false;
                }
            }
        } else {
            for seg in Self::path_segments(&self.path) {
                if !Self::advance_raw_token(raw_name, &mut cursor, &mut prev_token, seg, abi) {
                    return false;
                }
            }
            if let Some(func) = &self.func
                && !func.is_empty()
                && !Self::advance_raw_token(raw_name, &mut cursor, &mut prev_token, func, abi)
            {
                return false;
            }
        }
        true
    }

    /// 在 `raw_name[cursor..]` 中寻找下一个满足 Mangled 边界特征的标识符并推进游标
    #[inline]
    fn advance_raw_token<'a>(
        raw_name: &str,
        cursor: &mut usize,
        prev_token: &mut &'a str,
        token: &'a str,
        abi: SymAbi,
    ) -> bool {
        // C++ 析构函数 `~Foo` 在 Mangled 名中体现为类名 `Foo` + `D0`/`D1`/`D2`
        let clean_token = token.strip_prefix('~').unwrap_or(token);
        if clean_token.is_empty() {
            return true;
        }
        // 相邻同名段（如 C++ 构造/析构 `Foo::Foo` / `Foo::~Foo` 或 `foo::foo`）在 Mangled 中常合并或用 `0`/`C1` 表示
        if clean_token == *prev_token {
            return true;
        }
        *prev_token = clean_token;

        // 闭包标记在 Rust Legacy 中含 `"closure"`，在 Rust v0 中编码为 `"NC"`
        if ParsedSym::is_closure_marker(clean_token) {
            let raw_bytes = raw_name.as_bytes();
            return memmem::find(raw_bytes, b"closure").is_some()
                || memmem::find(raw_bytes, b"NC").is_some();
        }
        // 非纯 ASCII 标识符（如 `operator<<` 或 Punycode）直接放行交由 Demangle 处理
        if !clean_token.bytes().all(ParsedSym::is_ident_byte) {
            return true;
        }
        // C++ Itanium ABI 会将 `std`、`string` 等压缩为 2 字节 `St`、`Ss` 等含 `S` 的前缀
        // 必须优先校验且不推进 cursor，防止误匹配到符号末尾函数参数中的同名子串导致 cursor 越界
        if abi == SymAbi::Itanium && Self::is_itanium_std_substitution(clean_token) {
            let raw_bytes = raw_name.as_bytes();
            return memchr(b'S', raw_bytes).is_some()
                || memmem::find(raw_bytes, clean_token.as_bytes()).is_some();
        }
        // Swift ABI 会将标准库模块 `Swift` / `ObjectiveC` 压缩为 `s` / `So`
        if abi == SymAbi::Swift && (clean_token == "Swift" || clean_token == "ObjectiveC") {
            return true;
        }

        if Self::find_token_from(raw_name, *cursor, clean_token, cursor) {
            return true;
        }

        // Swift 驼峰子词替换（Word Substitution，如 `MyModule.MyClass` 中 `My` 被替换为 `0A`）兜底
        if abi == SymAbi::Swift
            && clean_token.bytes().skip(1).any(|b| b.is_ascii_uppercase())
            && raw_name[*cursor..].bytes().any(|b| b.is_ascii_uppercase())
        {
            return true;
        }

        // 回溯引用兜底：若从当前 cursor 往后找不到，但该标识符在 cursor 之前已出现过，
        // 则可能是 MSVC 索引替换(`0..9`)、Rust v0(`B_`) 或 Itanium(`S_`) 压缩了重复段，放行由阶段二精筛
        let mut dummy = 0;
        *cursor > 0 && Self::find_token_from(&raw_name[..*cursor], 0, clean_token, &mut dummy)
    }

    #[inline]
    fn find_token_from(
        haystack: &str,
        mut search_from: usize,
        clean_token: &str,
        out_cursor: &mut usize,
    ) -> bool {
        let bytes = haystack.as_bytes();
        let needle = clean_token.as_bytes();
        while search_from + needle.len() <= bytes.len() {
            if let Some(rel_pos) = memmem::find(&bytes[search_from..], needle) {
                let abs_pos = search_from + rel_pos;
                // 左边界不变式：在任何 Mangled 规则中，独立段标识符的起点绝不可能紧跟在小写字母 `a..=z` 之后
                if abs_pos == 0 || !bytes[abs_pos - 1].is_ascii_lowercase() {
                    *out_cursor = abs_pos + needle.len();
                    return true;
                }
                search_from = abs_pos + 1;
            } else {
                break;
            }
        }
        false
    }

    /// C++ Itanium ABI 中会被压缩为 `St`/`Sa`/`Sb`/`Ss`/`Si`/`So`/`Sd` 的标准库标识符
    #[inline]
    fn is_itanium_std_substitution(token: &str) -> bool {
        matches!(
            token,
            "std"
                | "allocator"
                | "basic_string"
                | "string"
                | "char_traits"
                | "basic_istream"
                | "istream"
                | "basic_ostream"
                | "ostream"
                | "basic_iostream"
                | "iostream"
        )
    }

    /// 【第二阶段：Demangle 后精确验证】基于 `name_only()` 解修饰结果的跳词子序列匹配
    fn matches_parsed(&self, parsed: &ParsedSym) -> bool {
        let total = parsed.seg_count();
        if total == 0 {
            return false;
        }

        // 1. 若指定了目标函数名 `func`
        if let Some(target_func) = &self.func
            && !target_func.is_empty()
        {
            if ParsedSym::is_closure_marker(target_func) {
                return parsed.has_closure_suffix && self.match_path_subsequence(parsed, total - 1);
            }
            if parsed.has_closure_suffix || parsed.segment(total - 1) != target_func {
                return false;
            }
            return self.match_path_subsequence(parsed, total - 1);
        }

        // 2. 若未指定 `func`（匹配 `path` 下的所有函数或闭包）
        // 若末尾是闭包段，则允许 `path` 匹配包括外层函数名及闭包段在内的全部路径；否则排除最后一个函数名段
        let path_len = if parsed.has_closure_suffix {
            total
        } else {
            total.saturating_sub(1)
        };
        self.match_path_subsequence(parsed, path_len)
    }

    /// 有序子序列（跳词）匹配：要求 `self.path` 中的每个段按顺序命中 `parsed` 的路径段，前后及中间允许间隔其他段
    #[inline]
    fn match_path_subsequence(&self, parsed: &ParsedSym, path_seg_len: usize) -> bool {
        let mut cursor = 0usize;
        for target_seg in Self::path_segments(&self.path) {
            if cursor >= path_seg_len {
                return false;
            }
            let is_target_closure = ParsedSym::is_closure_marker(target_seg);
            let mut found = false;
            while cursor < path_seg_len {
                let seg = parsed.segment(cursor);
                cursor += 1;
                if if is_target_closure {
                    ParsedSym::is_closure_marker(seg)
                } else {
                    seg == target_seg
                } {
                    found = true;
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }
}

/// 函数的惰性解析上下文
#[derive(Clone)]
pub struct FuncSymbol<'a> {
    cleaned_raw: &'a str,
    abi: SymAbi,
    parsed: OnceCell<&'static ParsedSym>,
}

impl<'a> FuncSymbol<'a> {
    #[inline]
    pub fn new(raw_name: &'a str) -> Self {
        let cleaned_raw = ParsedSym::strip_compiler_affixes(raw_name);
        Self {
            cleaned_raw,
            abi: SymAbi::detect(cleaned_raw),
            parsed: OnceCell::new(),
        }
    }

    #[inline]
    pub const fn raw_name(&self) -> &'a str {
        self.cleaned_raw
    }

    #[inline]
    const fn cleaned_raw(&self) -> &'a str {
        self.cleaned_raw
    }

    #[inline]
    fn parsed(&self) -> &'static ParsedSym {
        *self
            .parsed
            .get_or_init(|| ParsedSym::get_or_parse(self.cleaned_raw))
    }
}

/// 驻留于全局缓存中的路径段解析结果
struct ParsedSym {
    demangled: Box<str>,
    segments: Box<[(u16, u16)]>,
    has_closure_suffix: bool,
}

impl ParsedSym {
    #[inline]
    const fn is_ident_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    #[inline]
    fn is_closure_marker(s: &str) -> bool {
        s == "closure" || s == "{{closure}}" || (s.starts_with("{closure") && s.ends_with('}'))
    }

    /// 过滤 `<&mut Type as Trait>` 等复合类型语法中的非路径关键字
    #[inline]
    fn is_ignored_keyword(s: &str) -> bool {
        matches!(s, "as" | "mut" | "const" | "dyn")
    }

    #[inline]
    fn seg_count(&self) -> usize {
        self.segments.len()
    }

    #[inline]
    fn segment(&self, idx: usize) -> &str {
        let (start, end) = self.segments[idx];
        &self.demangled[start as usize..end as usize]
    }

    /// 全局缓存查询快路径
    #[inline]
    fn get_or_parse(cleaned_raw: &str) -> &'static Self {
        if let Some(sym) = SYM_CACHE.get(cleaned_raw) {
            return *sym;
        }
        Self::parse_and_cache(cleaned_raw)
    }

    /// 缓存未命中慢路径：在锁外完成 Demangle 与分词，仅在首次插入时驻留内存
    #[cold]
    #[inline(never)]
    fn parse_and_cache(cleaned_raw: &str) -> &'static Self {
        let key: Box<str> = Box::from(cleaned_raw);
        let parsed = Self::parse_owned(&key);
        *SYM_CACHE
            .entry(key)
            .or_insert_with(|| Box::leak(Box::new(parsed)))
    }

    fn parse_owned(cleaned_raw: &str) -> Self {
        let demangled: Box<str> = symbolic_common::Name::from(cleaned_raw)
            .demangle(symbolic_demangle::DemangleOptions::name_only())
            .map_or_else(|| Box::from(cleaned_raw), String::into_boxed_str);

        let mut buf = [(0u16, 0u16); MAX_PATH_SEGMENTS];
        let (seg_count, has_closure_suffix) = Self::tokenize(&demangled, &mut buf);

        Self {
            demangled,
            segments: Box::from(&buf[..seg_count as usize]),
            has_closure_suffix,
        }
    }

    /// 剥离 LLVM 优化器或链接器附加的前后缀
    pub(crate) fn strip_compiler_affixes(mut s: &str) -> &str {
        if let Some(rest) = s.strip_prefix('\x01') {
            s = rest;
        }
        // 剥离可选的 Windows DLL 导入表前缀或 LLVM SimplifyCFG 跳转表前缀
        if let Some(rest) = s
            .strip_prefix("__imp_")
            .or_else(|| s.strip_prefix("_imp_"))
            .or_else(|| s.strip_prefix("switch.table."))
        {
            s = rest;
        }
        // 处理 Windows x86 fastcall 前导 `@` 及 ELF `@GLIBC` / stdcall `@12` 尾缀
        if !s.as_bytes().starts_with(b"?") {
            s = s.strip_prefix('@').unwrap_or(s);
            if let Some(at_idx) = memchr(b'@', s.as_bytes()) {
                s = &s[..at_idx];
            }
        }
        let bytes = s.as_bytes();
        // 快速短路：绝大多数正常符号不含 '.'，单次 SIMD memchr 扫描即可返回
        let Some(first_dot) = memchr(b'.', bytes) else {
            return s;
        };
        if bytes.starts_with(b"_Z")
            || bytes.starts_with(b"__Z")
            || bytes.starts_with(b"_R")
            || bytes.starts_with(b"__R")
            || bytes.starts_with(b"_$s")
            || bytes.starts_with(b"$s")
        {
            let search_start = memrchr(b'$', &bytes[first_dot..])
                .map_or(first_dot, |rel_dollar| first_dot + rel_dollar + 1);
            let mut i = search_start;
            while i < bytes.len() {
                if let Some(rel) = memchr(b'.', &bytes[i..]) {
                    let dot = i + rel;
                    if (dot == 0 || bytes[dot - 1] != b'.')
                        && (dot + 1 == bytes.len() || bytes[dot + 1] != b'.')
                    {
                        return &s[..dot];
                    }
                    i = dot + 2;
                } else {
                    break;
                }
            }
            return s;
        }
        let tail = &bytes[first_dot..];
        let mut cut = tail.len();
        for suffix in [
            b".llvm.".as_slice(),
            b".cold".as_slice(),
            b".part.".as_slice(),
            b".constprop.".as_slice(),
            b".isra.".as_slice(),
            b".lto_priv.".as_slice(),
            b".localalias".as_slice(),
        ] {
            if let Some(idx) = memmem::find(&tail[..cut], suffix) {
                cut = idx;
            }
        }
        &s[..first_dot + cut]
    }

    fn tokenize(full: &str, segments: &mut [(u16, u16); MAX_PATH_SEGMENTS]) -> (u8, bool) {
        let bytes = full.as_bytes();
        let len = bytes.len();
        if len == 0 || len > u16::MAX as usize {
            return (0, false);
        }

        let mut seg_count = 0u8;
        let mut has_closure_suffix = false;
        let mut i = 0usize;

        while i < len {
            let b = bytes[i];

            // 识别独立的 Rust 闭包段（`::{{closure}}` 或 `::{closure#0}`）与其它花括号块（如 `::{constant#0}`）
            if b == b'{' {
                let start = i;
                i = Self::skip_balanced(bytes, i, b'{', b'}');
                if bytes[start..].starts_with(b"{{closure}}")
                    || bytes[start..].starts_with(b"{closure")
                {
                    has_closure_suffix = true;
                    if (seg_count as usize) < MAX_PATH_SEGMENTS {
                        segments[seg_count as usize] = (start as u16, i as u16);
                        seg_count += 1;
                    }
                }
                continue;
            }

            // 跳过 C++ 匿名命名空间 `(anonymous namespace)` 与 Rust Turbofish `::<...>`
            if b == b'(' && bytes[i..].starts_with(b"(anonymous namespace)") {
                i += "(anonymous namespace)".len();
                continue;
            }
            if b == b'<' && i > 0 && bytes[i - 1] == b':' {
                i = Self::skip_balanced(bytes, i, b'<', b'>');
                continue;
            }

            // 其它非标识符字符（且非 C++ 析构函数 `~`）一律作为分隔符跳过
            if !Self::is_ident_byte(b)
                && !(b == b'~' && i + 1 < len && Self::is_ident_byte(bytes[i + 1]))
            {
                i += 1;
                continue;
            }

            // 扫描单个完整标识符（特殊保护 C++ `operator<<` / `operator()` 等运算符名）
            let start = i;
            if bytes[i..].starts_with(b"operator")
                && (i + 8 < len && !Self::is_ident_byte(bytes[i + 8]))
            {
                i = Self::consume_cpp_operator(bytes, i + 8);
            } else {
                if bytes[i] == b'~' {
                    i += 1;
                }
                while i < len && Self::is_ident_byte(bytes[i]) {
                    i += 1;
                }
            }
            let end = i;

            // 记录有效路径段（若闭包内部继续嵌套了具名函数/静态变量，则重置 `has_closure_suffix`）
            let token = &full[start..end];
            if !Self::is_ignored_keyword(token) {
                has_closure_suffix = false;
                if (seg_count as usize) < MAX_PATH_SEGMENTS {
                    segments[seg_count as usize] = (start as u16, end as u16);
                    seg_count += 1;
                }
            }

            // 紧贴在标识符之后的 `<...>`、`[...]`、`(...)`、`{...}` 视为类型/函数泛型或 `{{vtable.shim}}` 整体跳过
            while i < len {
                match bytes[i] {
                    b'<' => i = Self::skip_balanced(bytes, i, b'<', b'>'),
                    b'[' => i = Self::skip_balanced(bytes, i, b'[', b']'),
                    b'(' => i = Self::skip_balanced(bytes, i, b'(', b')'),
                    b'{' => i = Self::skip_balanced(bytes, i, b'{', b'}'),
                    _ => break,
                }
            }
        }

        (seg_count, has_closure_suffix)
    }

    /// 扫描并越过 C++ `operator` 后的符号部分
    #[inline]
    fn consume_cpp_operator(bytes: &[u8], mut i: usize) -> usize {
        let len = bytes.len();
        while i < len && bytes[i] == b' ' {
            i += 1;
        }
        if i >= len {
            return i;
        }
        // 处理 `operator()` 与 `operator[]`（避免后续模板 `<T>` 被误吞）
        if i + 1 < len
            && ((bytes[i] == b'(' && bytes[i + 1] == b')')
                || (bytes[i] == b'[' && bytes[i + 1] == b']'))
        {
            return i + 2;
        }
        let op_start = i;
        while i < len {
            match bytes[i] {
                b':' if i + 1 < len && bytes[i + 1] == b':' => break,
                b'(' | b' ' => break,
                b'<' => {
                    // 仅当 `<` 位于运算符首字符时，才属于 `operator<` / `<<` / `<=` / `<<=` / `<=>`
                    if i == op_start {
                        i += 1;
                        if i < len {
                            if bytes[i] == b'<' {
                                i += 1;
                                if i < len && bytes[i] == b'=' {
                                    i += 1;
                                }
                            } else if bytes[i] == b'=' {
                                i += 1;
                                if i < len && bytes[i] == b'>' {
                                    i += 1;
                                }
                            }
                        }
                    }
                    break;
                }
                _ => i += 1,
            }
        }
        i
    }

    /// 使用 `memchr2` SIMD 跳跃配平括号，直接越过括号内部的大段标识符字符
    #[inline]
    fn skip_balanced(bytes: &[u8], mut i: usize, open: u8, close: u8) -> usize {
        let len = bytes.len();
        let mut depth = 0usize;
        while let Some(rel) = memchr2(open, close, &bytes[i..]) {
            i += rel;
            if bytes[i] == open {
                depth += 1;
            } else {
                // 忽略函数指针类型 `<fn() -> Ret>` 中的 `->`
                if close == b'>' && i > 0 && bytes[i - 1] == b'-' {
                    i += 1;
                    continue;
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            i += 1;
        }
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &[&str], func: Option<&str>) -> TargetFuncRule {
        TargetFuncRule {
            func: func.map(String::from),
            path: path.iter().map(|&s| String::from(s)).collect(),
            passes: Vec::new(),
            exclude: false,
        }
    }

    #[test]
    fn test_rust_fn() {
        let func = &[
            "_RNvNvNvCsd6AuMU2hSVg_4demo4main34___chunk_fn_5330808912240944689_71823___STATIC_HB2_1540182250",
            "__imp__RNvNvNtNtNtCs6pyUOHnsZyf_11lib_unknown6crypto4core2rp5rpp64s_6___MASK",
            "_RNvNvNtNtNtCs6pyUOHnsZyf_11lib_unknown6crypto4core3mix5mix644MULS",
            "_RNvNvNtNtNtCs8yVjgGcKdz0_6memchr4arch6x86_646memchr10memchr_raw2FN",
            "_RNvNvNvCsd6AuMU2hSVg_4demo4main34___chunk_fn_5330808912240944689_17123___STATIC_HB2_3678727133",
            "switch.table._RNvNtNtNtCskaZwRKfRSK3_3std3sys11personality3gcc24rust_eh_personality_impl",
            "_RNvNvNtNtCs6pyUOHnsZyf_11lib_unknown6crypto3mse14derive_r8_keys6PI_Q32",
            "anon.e88a446c5e09fa337d2383f77ab6944d.445",
            "_RNvNCNKNvNtNtCskaZwRKfRSK3_3std9panicking11panic_count17LOCAL_PANIC_COUNT0s_023___RUST_STD_INTERNAL_VAL",
        ];

        let r_demo_main = rule(&["demo", "main"], None);
        assert!(r_demo_main.matches(func[0]));
        assert!(r_demo_main.matches(func[4]));
        assert!(!r_demo_main.matches(func[1]));
        assert!(rule(&["demo", "main"], Some("__STATIC_HB2_1540182250")).matches(func[0]));

        let r_crypto = rule(&["lib_unknown", "crypto"], None);
        assert!(r_crypto.matches(func[1]));
        assert!(r_crypto.matches(func[2]));
        assert!(r_crypto.matches(func[6]));
        assert!(!r_crypto.matches(func[0]));

        assert!(rule(&["lib_unknown", "core", "rpp64"], Some("__MASK")).matches(func[1]));
        assert!(rule(&["lib_unknown", "mix", "mix64"], Some("MULS")).matches(func[2]));
        assert!(rule(&["lib_unknown", "mse", "derive_r8_keys"], Some("PI_Q32")).matches(func[6]));
        assert!(
            rule(
                &["memchr", "arch", "x86_64", "memchr", "memchr_raw"],
                Some("FN")
            )
            .matches(func[3])
        );
        assert!(rule(&["memchr", "memchr_raw"], None).matches(func[3]));
        assert!(
            rule(
                &["std", "sys", "personality", "gcc"],
                Some("rust_eh_personality_impl")
            )
            .matches(func[5])
        );
        assert!(rule(&["std", "personality"], None).matches(func[5]));
        assert!(rule(&["anon"], Some("445")).matches(func[7]));
        assert!(!r_crypto.matches(func[7]));
        assert!(
            rule(
                &["std", "panicking", "panic_count", "LOCAL_PANIC_COUNT"],
                Some("__RUST_STD_INTERNAL_VAL")
            )
            .matches(func[8])
        );
        assert!(
            rule(
                &["std", "panicking", "closure"],
                Some("__RUST_STD_INTERNAL_VAL")
            )
            .matches(func[8])
        );
        assert!(!rule(&["std", "constant"], None).matches(func[8]));

        let batch_rules = vec![r_demo_main, r_crypto];
        let matched_indices: Vec<usize> = func
            .iter()
            .enumerate()
            .filter_map(|(idx, &name)| {
                TargetFuncRule::matches_any(&batch_rules, name).then_some(idx)
            })
            .collect();
        assert_eq!(matched_indices, vec![0, 1, 2, 4, 6]);
    }

    #[test]
    fn test_rust_v0_complex_generics_and_monomorphization() {
        let btree_split = "_RNvMsU_NtNtNtCs1Xjjl6HmB4t_5alloc11collections5btree4nodeINtB5_6HandleINtB5_7NodeRefNtNtB5_6marker3MutyNtNtNtCs2eAofDMBLeW_5gimli4read6abbrev12AbbreviationNtB1m_4LeafENtB1m_2KVE15split_leaf_dataB1J_";
        assert!(
            rule(
                &["alloc", "collections", "btree", "node", "Handle"],
                Some("split_leaf_data")
            )
            .matches(btree_split)
        );
        assert!(rule(&["alloc", "btree", "Handle"], None).matches(btree_split));
        assert!(!rule(&["gimli", "read", "abbrev"], None).matches(btree_split));
        assert!(!rule(&["alloc", "NodeRef"], Some("split_leaf_data")).matches(btree_split));

        let option_map_or_else = "_RINvMNtCsVGna9UNWhe_4core6optionINtB3_6OptionReE11map_or_elseNtNtCs1Xjjl6HmB4t_5alloc6string6StringNCNvNtB11_3fmt6format0NvYeNtNtB11_6borrow7ToOwned8to_ownedECs6pyUOHnsZyf_11lib_unknown";
        assert!(
            rule(&["core", "option", "Option"], Some("map_or_else")).matches(option_map_or_else)
        );
        assert!(rule(&["core", "Option"], None).matches(option_map_or_else));
        assert!(!rule(&["alloc", "fmt", "format"], Some("closure")).matches(option_map_or_else));
        assert!(
            !rule(&["alloc", "borrow", "ToOwned"], Some("to_owned")).matches(option_map_or_else)
        );
        assert!(!rule(&["lib_unknown"], None).matches(option_map_or_else));

        let slice_ipnsort = "_RINvNtNtNtCsVGna9UNWhe_4core5slice4sort8unstable7ipnsortTjRNtNtCs2qr76hVOrIc_6object2pe11ImageSymbolENCINvMB6_SBS_20sort_unstable_by_keyjNCNvMs_NtNtNtNtCskaZwRKfRSK3_3std12backtrace_rs9symbolize5gimli4coffNtB2i_6Object5parse0E0EB2q_";
        assert!(
            rule(&["core", "slice", "sort", "unstable"], Some("ipnsort")).matches(slice_ipnsort)
        );
        assert!(rule(&["core", "slice", "sort"], None).matches(slice_ipnsort));
        assert!(!rule(&["object", "pe"], None).matches(slice_ipnsort));
        assert!(!rule(&["std", "backtrace_rs", "symbolize"], None).matches(slice_ipnsort));
        assert!(!rule(&["core", "slice"], Some("closure")).matches(slice_ipnsort));

        let chunk_closure_call_once = "_RNvYNCNvNvCsd6AuMU2hSVg_4demo4main34___chunk_fn_5330808912240944689_677s0_0INtNtNtCsVGna9UNWhe_4core3ops8function6FnOnceTQyyEE9call_onceB8_";
        assert!(rule(&["demo", "main"], None).matches(chunk_closure_call_once));
        assert!(rule(&["demo", "main", "closure"], None).matches(chunk_closure_call_once));
        assert!(
            rule(
                &[
                    "demo",
                    "main",
                    "__chunk_fn_5330808912240944689_677",
                    "closure",
                    "FnOnce"
                ],
                Some("call_once")
            )
            .matches(chunk_closure_call_once)
        );
        assert!(rule(&["demo", "main"], Some("call_once")).matches(chunk_closure_call_once));

        let ptr_drop_glue = "_RINvNtCsVGna9UNWhe_4core3ptr9drop_glueINtNvXsy_NtNtNtCs1Xjjl6HmB4t_5alloc11collections5btree3mapINtBJ_8IntoIterpppENtNtNtB4_3ops4drop4Drop4drop9DropGuardyINtNtB4_6result6ResultINtNtBP_4sync3ArcNtNtNtCs2eAofDMBLeW_5gimli4read6abbrev13AbbreviationsENtB39_5ErrorENtNtBP_5alloc6GlobalEECskaZwRKfRSK3_3std";
        assert!(rule(&["core", "ptr"], Some("drop_glue")).matches(ptr_drop_glue));
        assert!(rule(&["core", "ptr"], None).matches(ptr_drop_glue));
        assert!(!rule(&["alloc", "collections", "btree"], None).matches(ptr_drop_glue));
        assert!(!rule(&["core", "ptr"], Some("DropGuard")).matches(ptr_drop_glue));
    }

    #[test]
    fn test_rust_closures_and_traits() {
        let legacy_closure = "_ZN4demo4main28_$u7b$$u7b$closure$u7d$$u7d$17h1234567890abcdefE";
        let v0_closure = "_RNCNvCsd6AuMU2hSVg_4demo4main0";
        for &sym in &[legacy_closure, v0_closure] {
            assert!(rule(&["demo", "main"], Some("closure")).matches(sym));
            assert!(rule(&["demo", "main"], Some("{{closure}}")).matches(sym));
            assert!(rule(&["demo", "main"], None).matches(sym));
            assert!(rule(&["demo", "main", "closure"], None).matches(sym));
            assert!(!rule(&["demo"], Some("main")).matches(sym));
        }

        let trait_impl = "_RNvXCs1234_8my_crateNtB2_6ServerNtNtCs5678_4core3ops4Drop4drop";
        assert!(rule(&["my_crate", "Server", "Drop"], Some("drop")).matches(trait_impl));
        assert!(
            rule(&["mut", "my_crate", "Server", "as", "Drop"], Some("drop")).matches(trait_impl)
        );
    }

    #[test]
    fn test_cpp_itanium_and_msvc() {
        let std_sort = "_ZSt4sortIN9__gnu_cxx17__normal_iteratorIPiSt6vectorIiSaIiEEEEEvT_S7_";
        assert!(rule(&["std"], Some("sort")).matches(std_sort));

        let ctor = "_ZN3foo3BarC1Ev";
        let dtor = "_ZN3foo3BarD1Ev";
        assert!(rule(&["foo", "Bar"], Some("Bar")).matches(ctor));
        assert!(rule(&["foo", "Bar"], Some("~Bar")).matches(dtor));

        let op_lshift = "_ZN3foo3BarlsERSo";
        assert!(rule(&["foo", "Bar"], Some("operator<<")).matches(op_lshift));

        let op_call = "_ZNK3foo3BarclEi";
        assert!(rule(&["foo", "Bar"], Some("operator()")).matches(op_call));

        let msvc_sym = "?encrypt@AES@crypto@@QEAAXPEAE_K@Z";
        assert!(rule(&["crypto", "AES"], Some("encrypt")).matches(msvc_sym));
        assert!(rule(&["crypto"], None).matches(msvc_sym));
        assert!(!rule(&["AES", "crypto"], Some("encrypt")).matches(msvc_sym));
    }
}

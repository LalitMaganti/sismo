// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A compact, dependency-free tokenizer for the source/asm listing. No usable
// grammar for C/C++/Rust/asm ships in the UI, and a full editor (CodeMirror) is
// the wrong shape for a per-line annotated gutter, so this hand-rolls just
// enough lexing to colour keywords, types, strings, comments, numbers — and, for
// disassembly, mnemonics, registers and addresses. Tokens become classed spans
// (pf-sismo-syn--*) themed in styles.scss.

import m from 'mithril';

export type Lang = 'c' | 'rust' | 'asm' | 'plain';

// C/C++ and Rust share enough that one merged set is fine for colouring.
const KEYWORDS = new Set([
  // control flow + declarations (C/C++)
  'if',
  'else',
  'for',
  'while',
  'do',
  'switch',
  'case',
  'break',
  'continue',
  'return',
  'goto',
  'default',
  'sizeof',
  'typedef',
  'struct',
  'union',
  'enum',
  'class',
  'namespace',
  'template',
  'typename',
  'public',
  'private',
  'protected',
  'virtual',
  'override',
  'final',
  'new',
  'delete',
  'this',
  'nullptr',
  'true',
  'false',
  'using',
  'static',
  'const',
  'constexpr',
  'consteval',
  'volatile',
  'inline',
  'extern',
  'register',
  'auto',
  'operator',
  'throw',
  'try',
  'catch',
  'noexcept',
  'friend',
  'explicit',
  'mutable',
  'static_cast',
  'reinterpret_cast',
  'const_cast',
  'dynamic_cast',
  'decltype',
  'concept',
  'requires',
  'co_await',
  'co_return',
  'co_yield',
  // Rust
  'fn',
  'let',
  'mut',
  'impl',
  'trait',
  'pub',
  'use',
  'mod',
  'match',
  'loop',
  'in',
  'as',
  'dyn',
  'move',
  'ref',
  'unsafe',
  'async',
  'await',
  'crate',
  'super',
  'where',
  'self',
  'Self',
]);

const TYPES = new Set([
  'int',
  'char',
  'short',
  'long',
  'float',
  'double',
  'unsigned',
  'signed',
  'bool',
  'void',
  'wchar_t',
  'char16_t',
  'char32_t',
  'size_t',
  'ssize_t',
  'ptrdiff_t',
  'intptr_t',
  'uintptr_t',
  'int8_t',
  'int16_t',
  'int32_t',
  'int64_t',
  'uint8_t',
  'uint16_t',
  'uint32_t',
  'uint64_t',
  'u8',
  'u16',
  'u32',
  'u64',
  'u128',
  'usize',
  'i8',
  'i16',
  'i32',
  'i64',
  'i128',
  'isize',
  'f32',
  'f64',
  'str',
]);

export function langFromPath(path: string | null): Lang {
  if (path === null) return 'c';
  const ext = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  if (ext === 'rs') return 'rust';
  return 'c'; // c/cc/cpp/cxx/h/hpp/hh and unknown all lex close enough.
}

interface Tok {
  readonly cls: string | null; // null = plain (no span)
  readonly text: string;
}

function span(t: Tok): m.Children {
  if (t.cls === null) return t.text;
  return m(`span.pf-sismo-syn--${t.cls}`, t.text);
}

const ID_START = /[A-Za-z_$]/;
const ID_PART = /[A-Za-z0-9_$]/;
const DIGIT = /[0-9]/;

// Tokenise one source line, threading block-comment state across lines (so a
// `/* … */` that spans rows keeps colouring). Returns the rendered spans and the
// block-comment state at end of line.
export function highlightSource(
  line: string,
  lang: Lang,
  inBlockComment: boolean,
): {spans: m.Children; open: boolean} {
  if (lang === 'plain') return {spans: line, open: false};
  const toks: Tok[] = [];
  let i = 0;
  let open = inBlockComment;
  const n = line.length;

  const flushPlain = (from: number, to: number) => {
    if (to > from) toks.push({cls: null, text: line.slice(from, to)});
  };

  while (i < n) {
    if (open) {
      const end = line.indexOf('*/', i);
      if (end === -1) {
        toks.push({cls: 'com', text: line.slice(i)});
        i = n;
      } else {
        toks.push({cls: 'com', text: line.slice(i, end + 2)});
        i = end + 2;
        open = false;
      }
      continue;
    }
    const c = line[i];
    const c2 = line.slice(i, i + 2);
    if (c2 === '//') {
      toks.push({cls: 'com', text: line.slice(i)});
      break;
    }
    if (c2 === '/*') {
      const end = line.indexOf('*/', i + 2);
      if (end === -1) {
        toks.push({cls: 'com', text: line.slice(i)});
        open = true;
        i = n;
      } else {
        toks.push({cls: 'com', text: line.slice(i, end + 2)});
        i = end + 2;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      const start = i;
      i++;
      while (i < n) {
        if (line[i] === '\\') {
          i += 2;
          continue;
        }
        if (line[i] === c) {
          i++;
          break;
        }
        i++;
      }
      toks.push({cls: 'str', text: line.slice(start, i)});
      continue;
    }
    if (DIGIT.test(c)) {
      const start = i;
      while (i < n && /[0-9a-fA-FxXbBoO._']/.test(line[i])) i++;
      // numeric suffixes (u, l, f, …) and Rust's i32/u64 style tails.
      while (i < n && /[uUlLfF]/.test(line[i])) i++;
      toks.push({cls: 'num', text: line.slice(start, i)});
      continue;
    }
    if (ID_START.test(c)) {
      const start = i;
      while (i < n && ID_PART.test(line[i])) i++;
      const word = line.slice(start, i);
      const cls = TYPES.has(word) ? 'type' : KEYWORDS.has(word) ? 'kw' : null;
      toks.push({cls, text: word});
      continue;
    }
    // Run of plain characters (operators, punctuation, whitespace).
    const start = i;
    i++;
    while (
      i < n &&
      !ID_START.test(line[i]) &&
      !DIGIT.test(line[i]) &&
      line[i] !== '"' &&
      line[i] !== "'" &&
      line.slice(i, i + 2) !== '//' &&
      line.slice(i, i + 2) !== '/*'
    ) {
      i++;
    }
    flushPlain(start, i);
  }
  return {spans: toks.map(span), open};
}

const REGISTER =
  /^(?:[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p|r(?:8|9|1[0-5])[dwb]?|[abcdsbp]l|[xy]mm\d+|[wx](?:[12]?\d|3[01]|zr)|sp|lr|pc|v\d+|d\d+|s\d+|q\d+|cs|ds|es|fs|gs|ss|rip|eip)$/;

// Tokenise one disassembly line: first word is the mnemonic, hex/`$`-immediates
// are addresses, known register names are highlighted, the rest is plain.
export function highlightAsm(text: string): m.Children {
  const parts = text.split(/(\s+|,|\(|\)|\[|\]|\+|\*|:)/);
  let seenMnemonic = false;
  const out: m.Children[] = [];
  for (const p of parts) {
    if (p === '') continue;
    if (/^\s+$/.test(p)) {
      out.push(p);
      continue;
    }
    if (!seenMnemonic && /^[a-z][a-z0-9.]*$/i.test(p)) {
      seenMnemonic = true;
      out.push(m('span.pf-sismo-syn--mn', p));
      continue;
    }
    if (/^\$?[+-]?0x[0-9a-f]+$/i.test(p) || /^#?-?\d+$/.test(p)) {
      out.push(m('span.pf-sismo-syn--num', p));
      continue;
    }
    if (REGISTER.test(p.replace(/^%/, ''))) {
      out.push(m('span.pf-sismo-syn--reg', p));
      continue;
    }
    out.push(p);
  }
  return out;
}

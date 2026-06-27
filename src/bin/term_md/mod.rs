// Shardnet - Serverless peer-to-peer encrypted file storage and messaging
// Copyright (C) 2026 Anthony Clicheroux
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
// Terminal markdown renderer — ANSI escape codes, no external deps.

use std::io::Write;

const RESET:  &str = "\x1b[0m";
const BOLD:   &str = "\x1b[1m";
const DIM:    &str = "\x1b[2m";
const ITALIC: &str = "\x1b[3m";
const UNDER:  &str = "\x1b[4m";
const CYAN:   &str = "\x1b[36m";
const BCYAN:  &str = "\x1b[96m";
const YELLOW: &str = "\x1b[33m";

pub fn render_header(filename: &str) {
    render_header_inner(filename, &mut std::io::stdout());
}

pub fn render_header_to_string(filename: &str) -> String {
    let mut buf = Vec::new();
    render_header_inner(filename, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn render_header_inner<W: Write>(filename: &str, w: &mut W) {
    let _ = writeln!(w, "{DIM}  ─────────────────────────────────────{RESET}");
    let _ = writeln!(w, "{BOLD}{CYAN}  {filename}{RESET}");
    let _ = writeln!(w, "{DIM}  ─────────────────────────────────────{RESET}");
    let _ = writeln!(w);
}

/// Render a markdown string to stdout with ANSI formatting.
pub fn render(md: &str) {
    render_inner(md, &mut std::io::stdout());
}

/// Render a markdown string to a String with ANSI formatting.
pub fn render_to_string(md: &str) -> String {
    let mut buf = Vec::new();
    render_inner(md, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn render_inner<W: Write>(md: &str, w: &mut W) {
    let lines: Vec<&str> = md.lines().collect();
    let total = lines.len();
    let mut i = 0;

    while i < total {
        let line = lines[i];
        let trimmed = line.trim();

        // Fenced code block
        if trimmed.starts_with("```") {
            let lang = trimmed.trim_start_matches('`').trim();
            if lang.is_empty() {
                let _ = writeln!(w, "{DIM}  ╶──────────────{RESET}");
            } else {
                let _ = writeln!(w, "{DIM}  ╶─ {lang} ─{RESET}");
            }
            i += 1;
            while i < total && !lines[i].trim().starts_with("```") {
                let _ = writeln!(w, "{YELLOW}  {}{RESET}", lines[i]);
                i += 1;
            }
            let _ = writeln!(w, "{DIM}  ╶──────────────{RESET}");
            i += 1;
            continue;
        }

        // ATX headings (require space after # characters)
        if trimmed.starts_with('#') {
            let level = trimmed.chars().take_while(|&c| c == '#').count().min(6);
            let after = &trimmed[level..];
            if after.is_empty() || after.starts_with(' ') {
                let text = after.trim();
                match level {
                    1 => {
                        let _ = writeln!(w);
                        let _ = writeln!(w, "  {BCYAN}{BOLD}{UNDER}{}{RESET}", inline(text));
                        let _ = writeln!(w, "{DIM}  ─────────────────────────────────────{RESET}");
                    }
                    2 => {
                        let _ = writeln!(w);
                        let _ = writeln!(w, "  {CYAN}{BOLD}{}{RESET}", inline(text));
                    }
                    3 => { let _ = writeln!(w, "  {BOLD}{}{RESET}", inline(text)); }
                    _ => { let _ = writeln!(w, "  {BOLD}{DIM}{}{RESET}", inline(text)); }
                }
                i += 1;
                continue;
            }
        }

        // Horizontal rule
        let is_hr = trimmed.len() >= 3
            && (trimmed.chars().all(|c| c == '-')
                || trimmed.chars().all(|c| c == '_')
                || trimmed.chars().all(|c| c == '*'));
        if is_hr {
            let _ = writeln!(w, "{DIM}  ─────────────────────────────────────{RESET}");
            i += 1;
            continue;
        }

        // Blockquote
        if trimmed.starts_with("> ") || trimmed == ">" {
            let content = trimmed.strip_prefix("> ").unwrap_or("");
            let _ = writeln!(w, "{DIM}{ITALIC}  │ {}{RESET}", inline(content));
            i += 1;
            continue;
        }

        // Unordered list
        if trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with("+ ")
        {
            let content = &trimmed[2..];
            let src_indent = line.len() - line.trim_start().len();
            let pad = "  ".repeat(1 + src_indent / 2);
            let _ = writeln!(w, "{pad}{CYAN}•{RESET} {}", inline(content));
            i += 1;
            continue;
        }

        // Ordered list
        if let Some((num, content)) = parse_ol(trimmed) {
            let _ = writeln!(w, "  {CYAN}{num}.{RESET} {}", inline(content));
            i += 1;
            continue;
        }

        // Empty line
        if trimmed.is_empty() {
            let _ = writeln!(w);
            i += 1;
            continue;
        }

        // Regular paragraph line
        let _ = writeln!(w, "  {}", inline(line));
        i += 1;
    }
}

fn parse_ol(s: &str) -> Option<(&str, &str)> {
    let num_end = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if num_end == 0 { return None; }
    let rest = &s[num_end..];
    if rest.starts_with(". ") {
        Some((&s[..num_end], &rest[2..]))
    } else {
        None
    }
}

fn find_double(bytes: &[u8], start: usize, b: u8) -> Option<usize> {
    let n = bytes.len();
    let mut i = start;
    while i + 1 < n {
        if bytes[i] == b && bytes[i + 1] == b { return Some(i); }
        i += 1;
    }
    None
}

pub fn inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 32);
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        let b = bytes[i];

        if b == b'`' {
            if let Some(end) = bytes[i + 1..].iter().position(|&x| x == b'`') {
                out.push_str(YELLOW);
                out.push_str(&s[i + 1..i + 1 + end]);
                out.push_str(RESET);
                i += 2 + end;
                continue;
            }
        }

        if b == b'[' {
            if let Some(te) = bytes[i + 1..].iter().position(|&x| x == b']') {
                let text_end = i + 1 + te;
                if text_end + 1 < n && bytes[text_end + 1] == b'(' {
                    if let Some(ue) = bytes[text_end + 2..].iter().position(|&x| x == b')') {
                        let url_end = text_end + 2 + ue;
                        out.push_str(CYAN);
                        out.push_str(&s[i + 1..text_end]);
                        out.push_str(RESET);
                        let url = &s[text_end + 2..url_end];
                        if !url.is_empty() {
                            out.push_str(DIM);
                            out.push_str(" (");
                            out.push_str(url);
                            out.push(')');
                            out.push_str(RESET);
                        }
                        i = url_end + 1;
                        continue;
                    }
                }
            }
        }

        if b == b'*' && i + 1 < n && bytes[i + 1] == b'*' {
            if let Some(p) = find_double(bytes, i + 2, b'*') {
                out.push_str(BOLD);
                out.push_str(&s[i + 2..p]);
                out.push_str(RESET);
                i = p + 2;
                continue;
            }
        }

        if b == b'_' && i + 1 < n && bytes[i + 1] == b'_' {
            if let Some(p) = find_double(bytes, i + 2, b'_') {
                out.push_str(BOLD);
                out.push_str(&s[i + 2..p]);
                out.push_str(RESET);
                i = p + 2;
                continue;
            }
        }

        if b == b'~' && i + 1 < n && bytes[i + 1] == b'~' {
            if let Some(p) = find_double(bytes, i + 2, b'~') {
                out.push_str(DIM);
                out.push_str(&s[i + 2..p]);
                out.push_str(RESET);
                i = p + 2;
                continue;
            }
        }

        if b == b'*' && (i + 1 >= n || bytes[i + 1] != b'*') {
            let start = i + 1;
            if let Some(rel) = bytes[start..].iter().position(|&x| x == b'*') {
                let end = start + rel;
                if end > start {
                    out.push_str(ITALIC);
                    out.push_str(&s[start..end]);
                    out.push_str(RESET);
                    i = end + 1;
                    continue;
                }
            }
        }

        if b == b'_' && (i + 1 >= n || bytes[i + 1] != b'_') {
            let start = i + 1;
            if let Some(rel) = bytes[start..].iter().position(|&x| x == b'_') {
                let end = start + rel;
                if end > start {
                    out.push_str(ITALIC);
                    out.push_str(&s[start..end]);
                    out.push_str(RESET);
                    i = end + 1;
                    continue;
                }
            }
        }

        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

//! Node.js (v24) `path.posix` / `path.win32` `isAbsolute` and `normalize` semantics.
//!
//! Filesystem grants are accepted only when their root is absolute and already in
//! normal form for its declared dialect, so a grant can never smuggle `..`, redundant
//! separators, drive-relative forms or reserved device names past an enforcement
//! layer that compares prefixes. The algorithms are ported line by line from Node,
//! including the CVE-2024-36139 and reserved-device-name hardening, and operate on
//! UTF-16 code units exactly as JavaScript does.

const SLASH: u16 = b'/' as u16;
const BACKSLASH: u16 = b'\\' as u16;
const DOT: u16 = b'.' as u16;
const COLON: u16 = b':' as u16;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn text(u: &[u16]) -> String {
    String::from_utf16_lossy(u)
}

fn is_posix_sep(c: u16) -> bool {
    c == SLASH
}

fn is_win_sep(c: u16) -> bool {
    c == SLASH || c == BACKSLASH
}

fn index_of(haystack: &[u16], needle: u16, from: usize) -> Option<usize> {
    haystack.iter().skip(from).position(|c| *c == needle).map(|p| p + from)
}

fn last_index_of(haystack: &[u16], needle: u16) -> Option<usize> {
    haystack.iter().rposition(|c| *c == needle)
}

/// Node's internal `normalizeString`: resolves `.` and `..` segments.
fn normalize_string(path: &[u16], allow_above_root: bool, separator: u16, is_sep: fn(u16) -> bool) -> Vec<u16> {
    let mut res: Vec<u16> = Vec::new();
    let mut last_segment_length: usize = 0;
    let mut last_slash: Option<usize> = None; // -1 as None
    let mut dots: i32 = 0;
    let mut code: u16 = 0;
    let mut i = 0;
    while i <= path.len() {
        if i < path.len() {
            code = path[i];
        } else if is_sep(code) {
            break;
        } else {
            code = SLASH;
        }
        if is_sep(code) {
            let previous_was_slash = match last_slash {
                Some(l) => l + 1 == i,
                None => i == 0,
            };
            if previous_was_slash || dots == 1 {
                // no-op
            } else if dots == 2 {
                let n = res.len();
                if n < 2 || last_segment_length != 2 || res[n - 1] != DOT || res[n - 2] != DOT {
                    if n > 2 {
                        match last_index_of(&res, separator) {
                            None => {
                                res.clear();
                                last_segment_length = 0;
                            }
                            Some(index) => {
                                res.truncate(index);
                                last_segment_length = match last_index_of(&res, separator) {
                                    Some(l) => res.len() - 1 - l,
                                    None => res.len(),
                                };
                            }
                        }
                        last_slash = Some(i);
                        dots = 0;
                        i += 1;
                        continue;
                    } else if n != 0 {
                        res.clear();
                        last_segment_length = 0;
                        last_slash = Some(i);
                        dots = 0;
                        i += 1;
                        continue;
                    }
                }
                if allow_above_root {
                    if !res.is_empty() {
                        res.push(separator);
                    }
                    res.extend_from_slice(&[DOT, DOT]);
                    last_segment_length = 2;
                }
            } else {
                let start = last_slash.map_or(0, |l| l + 1);
                if !res.is_empty() {
                    res.push(separator);
                }
                res.extend_from_slice(&path[start..i]);
                last_segment_length = i - start;
            }
            last_slash = Some(i);
            dots = 0;
        } else if code == DOT && dots != -1 {
            dots += 1;
        } else {
            dots = -1;
        }
        i += 1;
    }
    res
}

pub fn posix_is_absolute(path: &str) -> bool {
    path.as_bytes().first() == Some(&b'/')
}

pub fn posix_normalize(path: &str) -> String {
    let p = units(path);
    if p.is_empty() {
        return ".".into();
    }
    let is_absolute = p[0] == SLASH;
    let trailing = p[p.len() - 1] == SLASH;
    let mut out = normalize_string(&p, !is_absolute, SLASH, is_posix_sep);
    if out.is_empty() {
        if is_absolute {
            return "/".into();
        }
        return if trailing { "./".into() } else { ".".into() };
    }
    if trailing {
        out.push(SLASH);
    }
    if is_absolute {
        format!("/{}", text(&out))
    } else {
        text(&out)
    }
}

fn is_device_root(c: u16) -> bool {
    (u16::from(b'A')..=u16::from(b'Z')).contains(&c) || (u16::from(b'a')..=u16::from(b'z')).contains(&c)
}

const WINDOWS_RESERVED_NAMES: [&str; 28] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// JavaScript `String.prototype.slice(start, end)` index resolution.
fn js_slice(s: &[u16], start: isize, end: isize) -> &[u16] {
    #[allow(clippy::cast_possible_wrap)]
    let len = s.len() as isize;
    let resolve = |i: isize| if i < 0 { (len + i).max(0) } else { i.min(len) };
    let (from, to) = (resolve(start), resolve(end));
    #[allow(clippy::cast_sign_loss)]
    if from >= to {
        &[]
    } else {
        &s[from as usize..to as usize]
    }
}

/// Node's `isWindowsReservedName(path, colonIndex)` with `colonIndex` possibly -1.
fn is_windows_reserved_name(path: &[u16], colon_index: isize) -> bool {
    let device = text(js_slice(path, 0, colon_index)).to_uppercase();
    WINDOWS_RESERVED_NAMES.contains(&device.as_str())
}

fn signed_index(index: Option<usize>) -> isize {
    #[allow(clippy::cast_possible_wrap)]
    index.map_or(-1, |i| i as isize)
}

pub fn win32_is_absolute(path: &str) -> bool {
    let p = units(path);
    match p.first() {
        None => false,
        Some(&c) => is_win_sep(c) || (p.len() > 2 && is_device_root(c) && p[1] == COLON && is_win_sep(p[2])),
    }
}

pub fn win32_normalize(path: &str) -> String {
    let p = units(path);
    let len = p.len();
    if len == 0 {
        return ".".into();
    }
    let mut root_end = 0;
    let mut device: Option<Vec<u16>> = None;
    let mut is_absolute = false;
    let code = p[0];
    if len == 1 {
        return if is_posix_sep(code) { "\\".into() } else { path.into() };
    }
    if is_win_sep(code) {
        is_absolute = true;
        if is_win_sep(p[1]) {
            let mut j = 2;
            let mut last = j;
            while j < len && !is_win_sep(p[j]) {
                j += 1;
            }
            if j < len && j != last {
                let first_part = p[last..j].to_vec();
                last = j;
                while j < len && is_win_sep(p[j]) {
                    j += 1;
                }
                if j < len && j != last {
                    last = j;
                    while j < len && !is_win_sep(p[j]) {
                        j += 1;
                    }
                    if j == len || j != last {
                        if first_part == [DOT] || first_part == [u16::from(b'?')] {
                            // Device root, e.g. \\.\PHYSICALDRIVE0
                            let mut d = units("\\\\");
                            d.extend_from_slice(&first_part);
                            device = Some(d);
                            root_end = 4;
                            let colon = signed_index(index_of(&p, COLON, 0));
                            let possible = js_slice(&p, 4, colon + 1).to_vec();
                            #[allow(clippy::cast_possible_wrap)]
                            if is_windows_reserved_name(&possible, possible.len() as isize - 1) {
                                let mut d = units("\\\\?\\");
                                d.extend_from_slice(&possible);
                                device = Some(d);
                                root_end = 4 + possible.len();
                            }
                        } else if j == len {
                            return format!("\\\\{}\\{}\\", text(&first_part), text(&p[last..]));
                        } else {
                            device = Some(units(&format!("\\\\{}\\{}", text(&first_part), text(&p[last..j]))));
                            root_end = j;
                        }
                    }
                }
            }
        } else {
            root_end = 1;
        }
    } else if let Some(colon) = index_of(&p, COLON, 0).filter(|c| *c > 0) {
        if is_device_root(code) && colon == 1 {
            device = Some(p[..2].to_vec());
            root_end = 2;
            if len > 2 && is_win_sep(p[2]) {
                is_absolute = true;
                root_end = 3;
            }
        } else if is_windows_reserved_name(&p, signed_index(Some(colon))) {
            device = Some(p[..=colon].to_vec());
            root_end = colon + 1;
        }
    }

    let mut tail = if root_end < len {
        normalize_string(&p[root_end..], !is_absolute, BACKSLASH, is_win_sep)
    } else {
        Vec::new()
    };
    if tail.is_empty() && !is_absolute {
        tail.push(DOT);
    }
    if !tail.is_empty() && is_win_sep(p[len - 1]) {
        tail.push(BACKSLASH);
    }
    let dot_prefixed = |tail: &[u16]| format!(".\\{}", text(tail));
    if !is_absolute && device.is_none() && p.contains(&COLON) {
        // CVE-2024-36139: a relative tail must not become drive- or stream-like.
        if tail.len() >= 2 && is_device_root(tail[0]) && tail[1] == COLON {
            return dot_prefixed(&tail);
        }
        let mut index = index_of(&p, COLON, 0);
        while let Some(i) = index {
            if i == len - 1 || is_win_sep(p[i + 1]) {
                return dot_prefixed(&tail);
            }
            index = index_of(&p, COLON, i + 1);
        }
    }
    if is_windows_reserved_name(&p, signed_index(index_of(&p, COLON, 0))) {
        let mut out = device.clone().unwrap_or_default();
        out.extend_from_slice(&tail);
        return dot_prefixed(&out);
    }
    match device {
        None => {
            if is_absolute {
                format!("\\{}", text(&tail))
            } else {
                text(&tail)
            }
        }
        Some(device) => {
            if is_absolute {
                format!("{}\\{}", text(&device), text(&tail))
            } else {
                format!("{}{}", text(&device), text(&tail))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_examples() {
        assert_eq!(posix_normalize("/foo/bar//baz/asdf/quux/.."), "/foo/bar/baz/asdf");
        assert_eq!(posix_normalize("a/../.."), "..");
        assert_eq!(posix_normalize("./"), "./");
        assert!(posix_is_absolute("/x") && !posix_is_absolute("x"));
    }

    #[test]
    fn win32_examples() {
        assert_eq!(win32_normalize("C:\\temp\\\\foo\\bar\\..\\"), "C:\\temp\\foo\\");
        assert_eq!(win32_normalize("C:////temp\\\\/\\/\\/foo/bar"), "C:\\temp\\foo\\bar");
        assert_eq!(win32_normalize("\\\\server\\share"), "\\\\server\\share\\");
        assert_eq!(win32_normalize("bC:"), ".\\bC:");
        assert_eq!(win32_normalize("CON:"), ".\\CON:.");
        assert!(win32_is_absolute("C:/x") && !win32_is_absolute("C:x"));
    }
}

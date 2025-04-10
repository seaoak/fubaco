use lazy_static::lazy_static;
use kana::wide2ascii;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub fn normalize_string<P: AsRef<str>>(s: P) -> String {
    // normalize string (Unicode NFKC, uppercase, no-whitespace, no-bullet)
    let s: &str = s.as_ref();
    let s = s.nfkc();
    let s = String::from_iter(s);
    let s = wide2ascii(&s);
    let s = s.chars();
    let s = s.filter(|c| !c.is_control());
    let s = s.filter(|c| !c.is_whitespace());
    // let s = s.filter(|c| !c.is_ascii_graphic());
    let s = s.filter(|c| c.is_alphanumeric() || *c == '@' || *c == '.' || *c == '-' || *c == '_');
    let s = String::from_iter(s);
    // let s = s.replace(&[' ', '　', '・'], "");
    let s = s.to_uppercase();
    s
}

pub fn is_non_english_alphabet_included(text: &str) -> bool {
    lazy_static! {
        static ref REGEX_NON_ENGLISH_ALPHABET: Regex = Regex::new(r"([\p{Alphabetic}&&[^\p{ASCII}\p{Hiragana}\p{Katakana}\p{Han}\p{Punct}ーａ-ｚＡ-Ｚ]])").unwrap();
    }
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("Ｖ")); // 全角アルファベットは許容する
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("５")); // 全角数字は許容する
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("＋")); // 全角のASCII記号は許容する
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("𠮷")); // \u9FFF より大きいコードポイントの漢字
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("賣")); // 繁体字の「売」
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("卖")); // 簡体字の「売」
    assert!(REGEX_NON_ENGLISH_ALPHABET.is_match("프로그래밍")); // ハングルで「プログラミング」
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("發")); // 繁体字の「発」
    assert!(!REGEX_NON_ENGLISH_ALPHABET.is_match("发")); // 簡体字の「発」
    assert!(REGEX_NON_ENGLISH_ALPHABET.is_match("В")); // キリル文字
    assert!(REGEX_NON_ENGLISH_ALPHABET.is_match("Д"));
    if let Some(caps) = REGEX_NON_ENGLISH_ALPHABET.captures(text) {
        println!("non-English alphabet: {}", &caps[1]);
        return true;
    }
    false
}

pub fn is_unicode_control_codepoint_included(text: &str) -> bool {
    lazy_static! {
        // GeneralCategory="Cf" is https://www.unicode.org/reports/tr44/tr44-24.html#General_Category_Values
        // GeneralCategory="Mn" is https://www.unicode.org/reports/tr24/
        static ref REGEX_UNICODE_CONTROL_CODEPOINT: Regex = Regex::new(r"([\p{Mn}\p{Cf}])").unwrap();
    }
    assert!(REGEX_UNICODE_CONTROL_CODEPOINT.is_match("J͎"));
    if let Some(caps) = REGEX_UNICODE_CONTROL_CODEPOINT.captures(text) {
        // https://ja.wikipedia.org/wiki/Unicode一覧_0000-0FFF
        println!("suspicious-control-codepoint-in-from: {} (codepoint=U+{:x})", &caps[1], u32::from(caps[1].chars().nth(0).unwrap()));
        return true;
    }
    false
}

//================================================================================
fn get_header_value(text: &str, name: &str) -> Option<String> {
    let lines = text.lines();
    let mut headers = Vec::<String>::new();
    lines.take_while(|line| line.len() > 0).for_each(|line| {
        if headers.len() == 0 || !line.starts_with([' ', '\t']) {
            headers.push(line.to_string());
        } else {
            headers.last_mut().unwrap().push_str(line.trim_start());
        }
    });
    headers.iter().filter(|line| line.to_ascii_lowercase().starts_with(&name.to_ascii_lowercase())).nth(0).map(|s| s[name.len()..].to_owned())
}

pub fn fix_incorrect_quoted_printable_text(raw_u8: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(Vec::from(raw_u8)).unwrap();
    let (header_part, body_part) = text.split_once("\r\n\r\n").unwrap();
    let content_type = if let Some(s) = get_header_value(&text, "Content-Type: ") {
        s
    } else {
        return text.into_bytes();
    };
    lazy_static! {
        // https://datatracker.ietf.org/doc/html/rfc2045
        // and also, I found that some characters which is not allowed in RFC2045 are used
        static ref REGEX_CONTENT_TYPE_FOR_MULTIPART: Regex = Regex::new(r##"^\s*multipart/[^;]+;(\s*\S+\s*;)*\s*boundary=["]?([-_=.,!#$%&^~|+*/?()<>0-9a-zA-Z]+)["]?\s*(;|$)"##).unwrap();
    }
    if let Some(caps) = REGEX_CONTENT_TYPE_FOR_MULTIPART.captures(&content_type) {
        println!("MIME multipart: boundary: {}", &caps[2]);
        let boundary = format!("\r\n--{}\r\n", &caps[2]); // include CRLF of previous line
        let regexp_for_last_part = Regex::new(&format!(r"(\r\n--{}(--)?\r\n(\s*\r\n)*)$", regex::escape(&caps[2]))).unwrap(); // include CRLF of previous line
        let last_part = match regexp_for_last_part.captures(&body_part) {
            Some(caps) => caps[1].to_owned(),
            None => return text.into_bytes(), // malformed mail format can not be processed
        };
        println!("MIME multipart: last part (dummy): {:?}", last_part);
        assert_eq!(&body_part[(body_part.len() - last_part.len())..], &last_part);
        let modified_body = format!("\r\n{}", &body_part[..(body_part.len() - last_part.len())]);  // insert CRLF at the first to match the boundary string, and remove last part
        let mut parts = modified_body.split(&boundary).map(|s| format!("{}\r\n", s)).collect::<Vec<_>>(); // compensate CRLF which is removed by str::split() and last_part
        let first_part = parts.remove(0)["\r\n".len()..].to_owned(); // remove previously-inserted CRLF (result may be empty string)
        println!("MIME multipart: first part (dummy): {:?}", first_part);
        println!("MIME multipart: number of parts: {}", parts.len());
        parts.iter().enumerate().for_each(|(index, s)| println!("MIME multipart: part[{}]: {} bytes", index, s.as_bytes().len()));
        let fixed = parts.into_iter().map(|s| fix_incorrect_quoted_printable_text(s.as_bytes())); // recursive call
        let mut list = Vec::new();
        list.push(header_part.to_owned().into_bytes());
        list.push("\r\n\r\n".to_owned().into_bytes());
        list.push(first_part.into_bytes());
        fixed.enumerate().for_each(|(index, part_u8)| {
            println!("MIME multipart fixed part[{}]: {} bytes", index, part_u8.len());
            list.push(boundary["\r\n".len()..].to_owned().into_bytes());
            list.push(part_u8);
        });
        list.push(last_part["\r\n".len()..].to_owned().into_bytes()); // skip CRLF of previous line
        return list.into_iter().flatten().collect();
    }
    if let Some(encoding) = get_header_value(&text, "Content-Transfer-Encoding: ") {
        if encoding.to_ascii_lowercase().contains("quoted-printable") {
            // fix incorrect quoted-printable encoding
            let fixed = body_part.replace("=\r\n..", "=\r\n.");
            if fixed.len() != body_part.len() {
                println!("Fix incorrect quoted-printable encoding: {}", body_part.len() - fixed.len());
            }
            let it = [header_part, "\r\n\r\n", &fixed].into_iter().flat_map(|s| s.to_owned().into_bytes());
            return it.collect();
        }
    }
    text.into_bytes()
}

use lazy_static::lazy_static;
use kana::wide2ascii;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

use crate::my_logger::prelude::*;

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

#[test]
fn test_normalize_string() {
    assert_eq!("012", normalize_string("012"));
    assert_eq!("012", normalize_string("０１２")); // zenkaku digit

    assert_eq!("ABC", normalize_string("ABC"));
    assert_eq!("ABC", normalize_string("abc"));
    assert_eq!("ABC", normalize_string("ＡＢＣ")); // zenkaku alphabet
    assert_eq!("ABC", normalize_string(" A B C "));
    assert_eq!("ABC", normalize_string("\nA\tB\0C\r")); // control codepoint
    assert_eq!("ABC", normalize_string("A　B　C")); // zenkaku-space

    assert_eq!("ABC", normalize_string("(ABC)"));
    assert_eq!("ABC", normalize_string("[ABC]"));
    assert_eq!("ABC", normalize_string("{ABC}"));
    assert_eq!("ABC", normalize_string("<ABC>"));

    assert_eq!("ABC", normalize_string("A(B)C"));
    assert_eq!("ABC", normalize_string("A[B]C"));
    assert_eq!("ABC", normalize_string("A{B}C"));
    assert_eq!("ABC", normalize_string("A<B>C"));

    assert_eq!("ABC", normalize_string("A!B!C"));
    assert_eq!("ABC", normalize_string("A\"B\"C"));
    assert_eq!("ABC", normalize_string("A#B#C"));
    assert_eq!("ABC", normalize_string("A$B$C"));
    assert_eq!("ABC", normalize_string("A%B%C"));
    assert_eq!("ABC", normalize_string("A&B&C"));
    assert_eq!("ABC", normalize_string("A'B'C"));
    assert_eq!("ABC", normalize_string("A=B=C"));

    assert_eq!("A@B@C", normalize_string("A@B@C"));
    assert_eq!("A.B.C", normalize_string("A.B.C"));
    assert_eq!("A-B-C", normalize_string("A-B-C"));
    assert_eq!("A_B_C", normalize_string("A_B_C"));
}

//================================================================================
pub fn is_keyword_matched_with_word_boundary(keyword: &str, text: &str) -> bool {
    // First, the keyword `ANA` should not match a string `BANANA`.
    // So we should consider WORD BOUNDARY.
    // Second, when the keyword is `Apple`, a string `Apple ID` should be matched.
    // But if we use the helper function `normalize_string()`, `Apple ID` is converted to `APPLEID`.
    // So we can not use the RegExp pattern `\b`.
    // This leads us to give up using the helper function `normalize_string()` directly.
    // Third, we should consider extra whitespaces at any position in the middle of a word (with evil intentions).

    let keyword = normalize_string(keyword);
    let re = {
        let s = &keyword;
        assert!(s.len() > 0);

        let first_char = s.chars().nth(0).unwrap();
        let last_char = s.chars().nth_back(0).unwrap();
        let prefix = if first_char.is_ascii_alphanumeric() { r"(^|[^a-zA-Z0-9])" } else { "" };
        let postfix = if last_char.is_ascii_alphanumeric() { r"([^a-zA-Z0-9]|$)" } else { "" };

        let escaped_elements = s.chars().map(|c| regex::escape(&c.to_string())).collect::<Vec<_>>();
        let pattern_with_any_extra_whitespace = escaped_elements.join(r"\s*");

        Regex::new(&format!("{}{}{}", prefix, pattern_with_any_extra_whitespace, postfix)).unwrap()
    };

    let text = text.nfc(); // not NFKC which is used in `normalize_string()`
    let text = text.to_string();
    let it = text.chars();
    let it = it.map(|c| normalize_string(&c.to_string()));
    let it = it.map(|s| if s.len() > 0 { s } else { " ".to_string() }); // replace empty element with a whitespace
    let converted_text: String = it.collect();

    re.is_match(&converted_text)
}

#[test]
fn test_is_keyword_matched() {
    assert!(is_keyword_matched_with_word_boundary("ANA", "ANA"));
    assert!(is_keyword_matched_with_word_boundary("ANA", " ANA")); // whitespace before keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", "ANA ")); // whitespace after keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", " ANA ")); // whitespaces around keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", "全日空ANA全日空")); // Japanese letters around keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", "■ANA■")); // Japanese letters around keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", "B\0ANA\0NA")); // control codepoint around keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", "B\nANA\nNA")); // control codepoint around keyword
    assert!(is_keyword_matched_with_word_boundary("ANA", "B_ANA_NA")); // symbols around keyword

    assert!(!is_keyword_matched_with_word_boundary("ANA", "BANANA"));
    assert!(!is_keyword_matched_with_word_boundary("ANA", "ANANA"));
    assert!(!is_keyword_matched_with_word_boundary("ANA", "BANA"));
    assert!(!is_keyword_matched_with_word_boundary("ANA", "B_ANANA"));
    assert!(!is_keyword_matched_with_word_boundary("ANA", "BANA_NA"));

    assert!(is_keyword_matched_with_word_boundary("ANA", "A N A")); // extra whitespaces in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "A　N　A")); // zenkaku-space in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "A\0N\0A")); // extra whitespaces in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "A\nN\nA")); // extra whitespaces in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "■A　N　A■")); // zenkaku-space in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "空A\0N\0A空")); // extra whitespaces in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "空A\nN\nA空")); // extra whitespaces in the middle of a word
    assert!(is_keyword_matched_with_word_boundary("ANA", "B A N A N A")); // extra whitespaces in the middle of and around a word
    assert!(!is_keyword_matched_with_word_boundary("ANA", "BA NA"));
    assert!(!is_keyword_matched_with_word_boundary("ANA", "AN AN"));
    assert!(!is_keyword_matched_with_word_boundary("ANA", "BA NA NA"));

    assert!(is_keyword_matched_with_word_boundary("Apple", "Apple ID"));
    assert!(is_keyword_matched_with_word_boundary("Apple", "the Apple"));
    assert!(!is_keyword_matched_with_word_boundary("Apple", "Apples"));
    assert!(!is_keyword_matched_with_word_boundary("Apple", "zapple"));

    assert!(is_keyword_matched_with_word_boundary("全", "全日空"));
    assert!(is_keyword_matched_with_word_boundary("日", "全日空"));
    assert!(is_keyword_matched_with_word_boundary("空", "全日空"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "全全全日空空空"));
    assert!(is_keyword_matched_with_word_boundary("全日空", " 全日空 "));
    assert!(is_keyword_matched_with_word_boundary("全日空", " 全 日 空 "));
    assert!(is_keyword_matched_with_word_boundary("全日空", "　全日空　")); // zenkaku-space
    assert!(is_keyword_matched_with_word_boundary("全日空", "全　日　空")); // zenkaku-space
    assert!(is_keyword_matched_with_word_boundary("全日空", "　全　日　空　")); // zenkaku-space
    assert!(is_keyword_matched_with_word_boundary("全日空", "■全日空■"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "\0全日空\0"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "全\0日\0空"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "\0全\0日\0空\0"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "\n全日空\n"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "全\n日\n空"));
    assert!(is_keyword_matched_with_word_boundary("全日空", "\n全\n日\n空\n"));

    assert!(is_keyword_matched_with_word_boundary("あい...お", "あい…お")); // SPECIAL CASE: a "three-dot leader" will be converted to three "period" by NFKC normalization
}

//================================================================================
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
        info!("non-English alphabet: {}", &caps[1]);
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
        info!("suspicious-control-codepoint-in-from: {} (codepoint=U+{:x})", &caps[1], u32::from(caps[1].chars().nth(0).unwrap()));
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
        debug!("MIME multipart: boundary: {}", &caps[2]);
        let boundary = format!("\r\n--{}\r\n", &caps[2]); // include CRLF of previous line
        let regexp_for_last_part = Regex::new(&format!(r"(\r\n--{}(--)?\r\n(\s*\r\n)*)$", regex::escape(&caps[2]))).unwrap(); // include CRLF of previous line
        let last_part = match regexp_for_last_part.captures(&body_part) {
            Some(caps) => caps[1].to_owned(),
            None => return text.into_bytes(), // malformed mail format can not be processed
        };
        debug!("MIME multipart: last part (dummy): {:?}", last_part);
        assert_eq!(&body_part[(body_part.len() - last_part.len())..], &last_part);
        let modified_body = format!("\r\n{}", &body_part[..(body_part.len() - last_part.len())]);  // insert CRLF at the first to match the boundary string, and remove last part
        let mut parts = modified_body.split(&boundary).map(|s| format!("{}\r\n", s)).collect::<Vec<_>>(); // compensate CRLF which is removed by str::split() and last_part
        let first_part = parts.remove(0)["\r\n".len()..].to_owned(); // remove previously-inserted CRLF (result may be empty string)
        debug!("MIME multipart: first part (dummy): {:?}", first_part);
        debug!("MIME multipart: number of parts: {}", parts.len());
        parts.iter().enumerate().for_each(|(index, s)| debug!("MIME multipart: part[{}]: {} bytes", index, s.as_bytes().len()));
        let fixed = parts.into_iter().map(|s| fix_incorrect_quoted_printable_text(s.as_bytes())); // recursive call
        let mut list = Vec::new();
        list.push(header_part.to_owned().into_bytes());
        list.push("\r\n\r\n".to_owned().into_bytes());
        list.push(first_part.into_bytes());
        fixed.enumerate().for_each(|(index, part_u8)| {
            debug!("MIME multipart fixed part[{}]: {} bytes", index, part_u8.len());
            list.push(boundary["\r\n".len()..].to_owned().into_bytes());
            list.push(part_u8);
        });
        list.push(last_part["\r\n".len()..].to_owned().into_bytes()); // skip CRLF of previous line
        return list.into_iter().flatten().collect();
    }
    if let Some(encoding) = get_header_value(&text, "Content-Transfer-Encoding: ") {
        if encoding.to_ascii_lowercase().contains("quoted-printable") {
            // fix incorrect quoted-printable encoding
            let fixed = body_part.replace("\r\n..", "\r\n.");
            if fixed.len() != body_part.len() {
                info!("Fix incorrect quoted-printable encoding: {}", body_part.len() - fixed.len());
            }
            let it = [header_part, "\r\n\r\n", &fixed].into_iter().flat_map(|s| s.to_owned().into_bytes());
            return it.collect();
        }
    }
    text.into_bytes()
}

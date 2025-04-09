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

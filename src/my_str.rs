use kana::wide2ascii;
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

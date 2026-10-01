use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::RangeInclusive;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::my_logger::prelude::*;
use crate::my_text_line_stream::take_first_line;

//====================================================================
lazy_static!{
    static ref LINE_TERMINATOR: String = "\r\n".to_string();
    static ref TERMINATOR_OF_CONTENTS_OF_RESPONSE: String = format!(".{}", &*LINE_TERMINATOR);
    static ref REGEX_FOR_NUMBER_OF_MESSAGES: Regex = Regex::new(r"(?i)\b()(\d+)( messages?)\b").unwrap(); // case-insensitive
    static ref REGEX_FOR_OCTETS: Regex = Regex::new(r"(?i)\b()(\d+)( octets?)\b").unwrap(); // case-insensitive
}

//====================================================================
pub fn my_regex_replace_group_2<'h, R, T>(re: &Regex, haystack: &'h str, rep: R) -> Cow<'h, str>
    where R: FnMut(&str) -> T,
          T: AsRef<str>,
{
    const NUM_OF_GROUPS: usize = 3;
    const INDEX_OF_TARGET_GROUP: usize = 2; // group index is 1-based (index 0 is used for entire string which is matched)
    assert!((1..=NUM_OF_GROUPS).contains(&INDEX_OF_TARGET_GROUP));

    assert_eq!(Some(1+NUM_OF_GROUPS), re.static_captures_len()); // `Regex::static_captures_len()` include the implicit group which index is zero
    let mut rep = rep; // avoid compiler warning
    re.replace(haystack, |caps: &Captures| {
        assert_eq!(1+NUM_OF_GROUPS, caps.len()); // `Captures::len()` include the implicit group which index is zero
        let mut it = caps.iter().map(|x| x.unwrap().as_str().to_string());
        let full_text = it.next().unwrap();
        let groups = Vec::from_iter(it);
        assert_eq!(NUM_OF_GROUPS, groups.len());
        assert_eq!(full_text, groups.join("")); // all characters should be captured (there is no character which is NOT included in any groups)

        let new_groups = groups.into_iter().enumerate().map(|(i, ss)| {
            // `ss.len()` may be zero
            if i + 1 == INDEX_OF_TARGET_GROUP {
                rep(&ss).as_ref().to_string()
            } else {
                ss
            }
        }).collect::<Vec<_>>();
        let new_text = new_groups.join("");
        Cow::Owned(new_text)
    })
}

pub fn my_regex_extract_group_2<T: FromStr>(re: &Regex, haystack: &str) -> Result<Option<T>> {
    let mut value = None;
    let _ = my_regex_replace_group_2(re, haystack, |ss| {
        value = Some(ss.to_string());
        "" // dummy
    });
    if value.is_none() {
        return Ok(None);
    }
    let ss = value.unwrap();
    match T::from_str(&ss) {
        Ok(x) => Ok(Some(x)),
        Err(_) => Err(anyhow!("can not convert matched string: {:?}", (&ss, &re, &haystack))),
    }
}

#[test]
#[should_panic]
fn test_001_my_regex_replace_group_2() {
    my_regex_replace_group_2(&Regex::new(r"a").unwrap(), "a b c", |_| ""); // regex should have exact three groups
}

#[test]
#[should_panic]
fn test_002_my_regex_replace_group_2() {
    my_regex_replace_group_2(&Regex::new(r"(a)").unwrap(), "a b c", |_| ""); // regex should have exact three groups
}

#[test]
#[should_panic]
fn test_003_my_regex_replace_group_2() {
    my_regex_replace_group_2(&Regex::new(r"(a)()").unwrap(), "a b c", |_| ""); // regex should have exact three groups
}

#[test]
#[should_panic]
fn test_004_my_regex_replace_group_2() {
    my_regex_replace_group_2(&Regex::new(r"()()(a)()").unwrap(), "a b c", |_| ""); // regex should have exact three groups
}

#[test]
#[should_panic]
fn test_005_my_regex_replace_group_2() {
    my_regex_replace_group_2(&Regex::new(r"()(a)() b").unwrap(), "a b c", |_| ""); // regex should NOT have any characters which are NOT included in any group
}

#[test]
fn test_100_my_regex_replace_group_2() {
    assert_eq!("a b c", my_regex_replace_group_2(&Regex::new(r"()(z)()").unwrap(), "a b c", |_| ""));
    assert_eq!("a B c", my_regex_replace_group_2(&Regex::new(r"(\s+)(\w)(\s+)").unwrap(), "a b c", |ss| ss.to_ascii_uppercase()));
    assert_eq!(Some("b".to_string()), my_regex_extract_group_2(&Regex::new(r"(\s+)(\w)(\s+)").unwrap(), "a b c").unwrap());
    assert_eq!(None, my_regex_extract_group_2::<usize>(&Regex::new(r"()(\d)()").unwrap(), "a b c").unwrap());
}

//====================================================================
#[allow(unused)]
trait MyIteratorChunkedPartition<B, C, F, T>
    where B: Default + Extend<T>,
          C: Default + Extend<B>,
          F: FnMut(&T) -> bool,
{
    fn chunked_partition(self, pred: F) -> (C, C);
}

impl<F, I, T> MyIteratorChunkedPartition<Vec<T>, Vec<Vec<T>>, F, T> for I
    where F: FnMut(&T) -> bool,
          I: Iterator<Item = T>
{
    fn chunked_partition(self, predicate: F) -> (Vec<Vec<T>>, Vec<Vec<T>>) {
        let mut predicate = predicate;
        let mut list_for_truthy: Vec<Vec<T>> = Vec::default();
        let mut list_for_falsy: Vec<Vec<T>> = Vec::default();

        let mut prev_flag: Option<bool> = None;
        for item in self {
            let flag = predicate(&item); // call `predicate()` only once for each item
            let target_list = if flag { &mut list_for_truthy } else { &mut list_for_falsy };
            if prev_flag != Some(flag) {
                let new_chunk = Vec::default();
                target_list.push(new_chunk);
            }
            assert!(!target_list.is_empty());
            let chunk = target_list.last_mut().unwrap();
            chunk.push(item);

            assert!(1 >= ((list_for_truthy.len() as isize) - (list_for_falsy.len() as isize)).abs(), "{:?}", (list_for_truthy.len(), list_for_falsy.len()));
            prev_flag = Some(flag);
        }
        assert!(1 >= ((list_for_truthy.len() as isize) - (list_for_falsy.len() as isize)).abs(), "{:?}", (list_for_truthy.len(), list_for_falsy.len()));

        (list_for_truthy, list_for_falsy)
    }
}

//====================================================================
fn is_ascii_printable(c: char) -> bool {
    // false for a SPACE (0x20)
    // same as `char::is_ascii_graphic()`
    c.is_ascii() && !c.is_ascii_control() && !c.is_ascii_whitespace()
}

pub trait MyIsAsciiPrintable {
    fn is_ascii_printable(self) -> bool;
}

impl MyIsAsciiPrintable for char {
    fn is_ascii_printable(self) -> bool {
        is_ascii_printable(self)
    }
}

impl MyIsAsciiPrintable for &char {
    fn is_ascii_printable(self) -> bool {
        is_ascii_printable(*self)
    }
}

//====================================================================
trait MyTrimSuffix<T> {
    fn my_trim_suffix<P: AsRef<[T]>>(&self, suffix: &P) -> &[T];
}

impl<T: PartialEq> MyTrimSuffix<T> for [T] {
    fn my_trim_suffix<P: AsRef<[T]>>(&self, suffix: &P) -> &[T] {
        let pattern = suffix.as_ref();
        if self.ends_with(pattern) {
            return &self[..(self.len() - pattern.len())];
        };
        &self[..]
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum MyAsciiParsedField {
    Separator(String),
    Word(String),
}

impl MyAsciiParsedField {
    pub fn parse<F>(ss: &str, is_separator: F) -> Result<Vec<Self>>
        where F: FnMut(char) -> bool,
    {
        let mut is_separator = is_separator; // avoid a compiler warning
        assert!(!ss.is_empty());
        if !ss.chars().all(|c| c.is_ascii_printable() || c.is_ascii_whitespace()) {
            return Err(anyhow!("invalid codepoint: {:?}", (&ss)));
        }
        let list = ss.chars().try_fold(Vec::new(), |list: Vec<Self>, c| {
            let mut list = list; // avoid a compiler warning
            let chunks: &[Self] = match (list.pop(), is_separator(c)) {
                (None, true) => &[Self::Separator(c.to_string())],
                (None, false) => &[Self::Word(c.to_string())],
                (Some(Self::Separator(s1)), true) => &[Self::Separator(s1 + c.to_string().as_str())],
                (Some(Self::Word(s1)), false) => &[Self::Word(s1 + c.to_string().as_str())],
                (Some(latest_chunk), true) => &[latest_chunk, Self::Separator(c.to_string())],
                (Some(latest_chunk), false) => &[latest_chunk, Self::Word(c.to_string())],
            };
            list.extend_from_slice(chunks);
            Result::<Vec<_>>::Ok(list)
        })?;
        assert!(!list.is_empty());
        assert!(list.iter().all(|field| !field.as_str().is_empty()));
        assert!(list.iter().all(|field| field.as_str().chars().all(|c| field.is_separator() == is_separator(c))));
        assert!(list.windows(2).all(|pair| pair[0].is_separator() != pair[1].is_separator()));
        assert_eq!(ss, list.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("")); // original string can be reconstructed
        Ok(list)
    }

    pub fn is_separator(&self) -> bool {
        assert!(!self.as_str().is_empty());
        match &self {
            Self::Separator(_) => true,
            Self::Word(_) => false,
        }
    }

    pub fn as_str(&self) -> &str {
        let ss = match &self {
            Self::Separator(ss) => ss,
            Self::Word(ss) => ss,
        };
        assert!(!ss.is_empty());
        ss.as_str()
    }
}

#[test]
#[allow(non_snake_case)]
fn test_001_MyAsciiParsedField() {
    fn parser(ss: &str) -> Result<Vec<MyAsciiParsedField>> {
        MyAsciiParsedField::parse(ss, |c| !c.is_ascii_printable())
    }

    assert!(parser("\0").is_err()); // NUL
    assert!(parser("あ").is_err()); // non-ASCII
    assert!(parser("　").is_err()); // full-width space

    assert!(parser("い\t").is_err()); // non-ASCII
    assert!(parser(" う").is_err()); // non-ASCII
    assert!(parser(" え\r").is_err()); // non-ASCII
    assert!(parser("a b c d わ f g").is_err()); // non-ASCII
    assert!(parser("a b c \0").is_err()); // NUL
    assert!(parser("a b cＤe f g").is_err()); // NUL

    assert_eq!(vec![MyAsciiParsedField::Separator(" ".to_string())], parser(" ").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Separator("\r".to_string())], parser("\r").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Separator("\n".to_string())], parser("\n").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Separator("\t".to_string())], parser("\t").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("0".to_string())], parser("0").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("a".to_string())], parser("a").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("A".to_string())], parser("A").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("!".to_string())], parser("!").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("(".to_string())], parser("(").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("|".to_string())], parser("|").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("\\".to_string())], parser("\\").unwrap());

    assert_eq!(vec![MyAsciiParsedField::Separator("   ".to_string())], parser("   ").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Separator(" \r\n".to_string())], parser(" \r\n").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("000".to_string())], parser("000").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("0a(@)".to_string())], parser("0a(@)").unwrap());

    assert_eq!(vec![MyAsciiParsedField::Separator("   ".to_string()), MyAsciiParsedField::Word("000".to_string())], parser("   000").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Separator(" \r\n".to_string()), MyAsciiParsedField::Word("abc".to_string())], parser(" \r\nabc").unwrap());

    assert_eq!(vec![MyAsciiParsedField::Word("000".to_string()), MyAsciiParsedField::Separator("   ".to_string())], parser("000   ").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("abc".to_string()), MyAsciiParsedField::Separator(" \r\n".to_string())], parser("abc \r\n").unwrap());

    assert_eq!(vec![MyAsciiParsedField::Separator("   ".to_string()), MyAsciiParsedField::Word("000".to_string()), MyAsciiParsedField::Separator(" \r\n".to_string())], parser("   000 \r\n").unwrap());
    assert_eq!(vec![MyAsciiParsedField::Word("000".to_string()), MyAsciiParsedField::Separator("   ".to_string()), MyAsciiParsedField::Word("abc".to_string())], parser("000   abc").unwrap());

    assert_eq!(vec![MyAsciiParsedField::Word("%".to_string()), MyAsciiParsedField::Separator(" ".to_string()), MyAsciiParsedField::Word("x".to_string()), MyAsciiParsedField::Separator("\n".to_string())], parser("% x\n").unwrap());
}

//====================================================================
#[allow(unused)]
trait MyPredAdaptorNot<T> {
    fn my_pred_not(&self) -> impl Fn(T) -> bool;
}

impl<F: Fn(T) -> bool, T> MyPredAdaptorNot<T> for F
{
    fn my_pred_not(&self) -> impl Fn(T) -> bool {
        move |value: T| !self(value)
    }
}

/*
trait MyPredAdaptorMutNot<T> {
    fn my_pred_not(&mut self) -> impl FnMut(T) -> bool;
}

impl<F: FnMut(T) -> bool, T> MyPredAdaptorMutNot<T> for F
{
    fn my_pred_not(&mut self) -> impl FnMut(T) -> bool {
        move |value: T| !self(value)
    }
}

trait MyPredAdaptorOnceNot<T> {
    fn my_pred_not(self) -> impl FnOnce(T) -> bool;
}

impl<F: FnOnce(T) -> bool, T> MyPredAdaptorOnceNot<T> for F
{
    fn my_pred_not(self) -> impl FnOnce(T) -> bool {
        move |value: T| !self(value)
    }
}
 */

#[allow(unused)]
fn my_pred_not<F: Fn(T) -> bool, T>(pred: F) -> impl Fn(T) -> bool
{
    move |value: T| !pred(value)
}

//====================================================================
pub trait MyIteratorIsUnique {
    fn is_unique(self) -> bool;
}

impl<I, T> MyIteratorIsUnique for I
    where I: Iterator<Item = T>,
          T: Hash + Eq,
{
    fn is_unique(self) -> bool {
        let mut table = HashSet::new();
        for item in self {
            let is_already_existed = table.insert(item);
            if is_already_existed {
                return false; // short-cut
            }
        }
        return true;
    }
}

//====================================================================
#[allow(unused)]
trait MyIteratorSelectTuple2<T, U>: Iterator<Item = (T, U)>
{
    fn tuple0(self) -> impl Iterator<Item = T>;
    fn tuple1(self) -> impl Iterator<Item = U>;
}

impl<I, T, U> MyIteratorSelectTuple2<T, U> for I
    where I: Iterator<Item = (T, U)>,
          Self: Sized,
{
    fn tuple0(self) -> impl Iterator<Item = T> {
        self.map(|t| t.0)
    }

    fn tuple1(self) -> impl Iterator<Item = U> {
        self.map(|t| t.1)
    }
}

//====================
#[allow(unused)]
trait MyIteratorSelectTuple2Ref<'a, T, U>: Iterator<Item = &'a (T, U)>
    where T: 'a,
          U: 'a,
{
    fn tuple0(self) -> impl Iterator<Item = &'a T>;
    fn tuple1(self) -> impl Iterator<Item = &'a U>;
}

impl<'a, I, T, U> MyIteratorSelectTuple2Ref<'a, T, U> for I
    where I: Iterator<Item = &'a (T, U)>,
          T: 'a,
          U: 'a,
          Self: Sized,
{
    fn tuple0(self) -> impl Iterator<Item = &'a T> {
        self.map(|t| &t.0)
    }

    fn tuple1(self) -> impl Iterator<Item = &'a U> {
        self.map(|t| &t.1)
    }
}

#[test]
fn test_001_tuple0() {
    assert_eq!(Some(3), [(3, 5)].into_iter().tuple0().nth(0));
    assert_eq!(Some(&3), [(3, 5)].iter().tuple0().nth(0));
}

//====================================================================
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum MyPop3Indicator { // not public
    // refer to "Section 3. Bsic Operation" in RFC1939
    Positive,
    Negative,
}

impl std::str::FromStr for MyPop3Indicator {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        assert!(!s.is_empty());
        let first_word = s.split(|c: char| !c.is_ascii_printable()).nth(0).unwrap(); // very relaxed separator
        match first_word {
            "+OK" => Ok(Self::Positive),
            "-ERR" => Ok(Self::Negative),
            _ => Err(anyhow!("not an indicator: {:?}", (&first_word, &s))),
        }
    }
}

impl TryFrom<&str> for MyPop3Indicator {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl std::fmt::Display for MyPop3Indicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ss = match &self {
            Self::Positive => "+OK",
            Self::Negative => "-ERR",
        };
        write!(f, "{}", ss)
    }
}

impl MyPop3Indicator {
    pub fn is_ok(&self) -> bool {
        match &self {
            Self::Positive => true,
            Self::Negative => false,
        }
    }

    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MyPop3Username(String); // for USER command

impl std::str::FromStr for MyPop3Username {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if !s.chars().all(|c| c.is_ascii_printable()) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<&str> for MyPop3Username {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl AsRef<str> for MyPop3Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3Password(String); // for PASS command

impl std::str::FromStr for MyPop3Password {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if !s.chars().all(|c| c.is_ascii_printable()) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<&str> for MyPop3Password {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl AsRef<str> for MyPop3Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3Digest(String); // MD5 digest string for APOP command

impl std::str::FromStr for MyPop3Digest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if !s.chars().all(|c| c.is_ascii_printable()) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<&str> for MyPop3Digest {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl AsRef<str> for MyPop3Digest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MyPop3UniqueID(String); // for UIDL command

impl std::str::FromStr for MyPop3UniqueID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // RFC1939 says "consisting of one to 70 characters in the range 0x21 to 0x7E"
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if s.len() > 70 {
            return Err(anyhow!("too long unique-id: {:?}", s));
        }
        if !s.chars().map(u32::from).all(|c| 0x21 <= c && c <= 0x7e) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<&str> for MyPop3UniqueID {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl AsRef<str> for MyPop3UniqueID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3UniqueID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3MessageNumber(u32); // for LIST command and others

impl std::str::FromStr for MyPop3MessageNumber {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // an integer of base-10 (i.e. decimal), starting with `1`
        // NOTE: to avoid DoS, assume `u32`.
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        match u32::from_str_radix(s, 10) {
            Err(_) => Err(anyhow!("not unsigned integer: {:?}", s)),
            Ok(0) => Err(anyhow!("zero is not allowed (starting with one): {:?}", s)),
            Ok(x) => Ok(Self(x)),
        }
    }
}

impl TryFrom<&str> for MyPop3MessageNumber {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl AsRef<u32> for MyPop3MessageNumber {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl std::fmt::Display for MyPop3MessageNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3NumberOfLines(u32); // for TOP command

impl std::str::FromStr for MyPop3NumberOfLines {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "a non-negative number of lines" in RFC1939
        // NOTE: to avoid DoS, assume `u32`.
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        match u32::from_str_radix(s, 10) {
            Err(_) => Err(anyhow!("not unsigned integer: {:?}", s)),
            Ok(x) => Ok(Self(x)),
        }
    }
}

impl TryFrom<&str> for MyPop3NumberOfLines {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl AsRef<u32> for MyPop3NumberOfLines {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl std::fmt::Display for MyPop3NumberOfLines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3NumberOfMessages(usize); // for STAT command and LIST_ALL command

impl std::str::FromStr for MyPop3NumberOfMessages {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        match usize::from_str_radix(s, 10) {
            Err(_) => Err(anyhow!("not unsigned integer: {:?}", s)),
            Ok(x) => Ok(Self(x)),
        }
    }
}

impl TryFrom<&str> for MyPop3NumberOfMessages {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl From<usize> for MyPop3NumberOfMessages {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl MyPop3NumberOfMessages {
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for MyPop3NumberOfMessages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3Octets(usize); // for STAT/LIST_ALL/LIST_SINGLE/RETR command

impl std::str::FromStr for MyPop3Octets {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        match usize::from_str_radix(s, 10) {
            Err(_) => Err(anyhow!("not unsigned integer: {:?}", s)),
            Ok(x) => Ok(Self(x)),
        }
    }
}

impl TryFrom<&str> for MyPop3Octets {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl From<usize> for MyPop3Octets {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl MyPop3Octets {
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for MyPop3Octets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MyPop3ScanListingItem { // for both `LIST_ALL` command and `LIST_SINGLE` command
    message_number: MyPop3MessageNumber,
    nbytes: MyPop3Octets,
    additional_information: Option<String>, // NOTE: this field is necessary to keep data of server resopnse as possible.
}

impl MyPop3ScanListingItem {
    const SEPARATOR: &'static str = " "; // RFC1939 says "followed by a single space"

    fn is_valid_nbytes(nbytes: &MyPop3Octets) -> bool {
        nbytes.as_usize() > 0
    }

    pub fn as_message_number(&self) -> &MyPop3MessageNumber {
        &self.message_number
    }

    pub fn as_nbytes(&self) -> &MyPop3Octets {
        &self.nbytes
    }

    pub fn to_tuple(&self) -> (MyPop3MessageNumber, MyPop3Octets) {
        (self.as_message_number().clone(), self.as_nbytes().clone())

    }

    pub fn rebuild_with_nbytes(&self, message_number: &MyPop3MessageNumber, new_nbytes: &MyPop3Octets) -> Self {
        assert_eq!(message_number, self.as_message_number(), "{:?}", (&message_number, &new_nbytes, &self));
        assert!(Self::is_valid_nbytes(new_nbytes), "{:?}", (&message_number, &new_nbytes, &self));
        Self {
            nbytes: new_nbytes.clone(),
            ..self.clone()
        }
    }
}

impl<T: AsRef<str>> TryFrom<&[T]> for MyPop3ScanListingItem {
    type Error = anyhow::Error;

    fn try_from(value: &[T]) -> std::result::Result<Self, Self::Error> {
        let args = value.into_iter().map(|s| s.as_ref().to_string()).collect::<Vec<_>>();
        if args.len() < 2 {
            // NOTE: RFC1939 says "This memo makes no requirement on what follows the message size in the scan listing."
            return Err(anyhow!("each scan-listing item should have at least two arguments: {:?}", (&args)));
        }
        if !args.iter().all(|s| s.chars().all(|c| c.is_ascii() && !c.is_ascii_control())) { // allow SPACE character
            return Err(anyhow!("each scan-listing item should contain printable ASCII characters only: {:?}", (&args)));
        }
        let message_number = MyPop3MessageNumber::from_str(&args[0]).or_else(|err| Err(anyhow!("1st field of scan-listing item should be a message number: {:?}", (err, &args[0], &args))))?;
        let nbytes = MyPop3Octets::from_str(&args[1]).or_else(|err| Err(anyhow!("2nd field of scan-listing item should be a non-negative integer: {:?}", (err, &args[1], &args))))?;
        if !Self::is_valid_nbytes(&nbytes) {
            return Err(anyhow!("invalid nbytes: {:?}", (&nbytes, &args)));
        }
        let additional_information = args.get(2..).map(|list| list.join(Self::SEPARATOR)); // may be `Some("")` when only one extra SPACE character exists at the end of line
        Ok(Self {
            message_number,
            nbytes,
            additional_information,
        })
    }
}

impl std::str::FromStr for MyPop3ScanListingItem {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        let fields = s.split(Self::SEPARATOR).map(|s| s.to_string()).collect::<Vec<_>>();
        Self::try_from(fields.as_ref())
    }
}

impl Into<(MyPop3MessageNumber, MyPop3Octets)> for MyPop3ScanListingItem {
    fn into(self) -> (MyPop3MessageNumber, MyPop3Octets) {
        self.to_tuple()
    }
}

impl std::fmt::Display for MyPop3ScanListingItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = vec![self.message_number.to_string(), self.nbytes.to_string()];
        if self.additional_information.is_some() {
            fields.push(self.additional_information.clone().unwrap());
        }
        write!(f, "{}", fields.join(Self::SEPARATOR))
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MyPop3UniqueIdListingItem { // for both `UIDL_ALL` command and `UIDL_SINGLE` command
    message_number: MyPop3MessageNumber,
    unique_id: MyPop3UniqueID,
}

impl MyPop3UniqueIdListingItem {
    const SEPARATOR: &'static str = " "; // RFC1939 says "followed by a single space"

    pub fn as_message_number(&self) -> &MyPop3MessageNumber {
        &self.message_number
    }

    pub fn as_unique_id(&self) -> &MyPop3UniqueID {
        &self.unique_id
    }

    pub fn to_tuple(&self) -> (MyPop3MessageNumber, MyPop3UniqueID) {
        (self.as_message_number().clone(), self.as_unique_id().clone())
    }
}

impl<T: AsRef<str>> TryFrom<&[T]> for MyPop3UniqueIdListingItem {
    type Error = anyhow::Error;

    fn try_from(value: &[T]) -> std::result::Result<Self, Self::Error> {
        let args = value.into_iter().map(|s| s.as_ref()).collect::<Vec<_>>();
        if args.len() != 2 {
            // RFC1939 says "No information follows the unique-id in the unique-id listing."
            return Err(anyhow!("each \"unique-id listing\" item should have exactly two arguments: {:?}", (&args)));
        }
        let message_number = args[0].try_into()?;
        let unique_id = args[1].try_into()?;
        Ok(Self {
            message_number,
            unique_id,
        })
    }
}

impl std::str::FromStr for MyPop3UniqueIdListingItem {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        let fields = s.split(Self::SEPARATOR).map(|s| s.to_string()).collect::<Vec<_>>();
        Self::try_from(fields.as_ref())
    }
}

impl Into<(MyPop3MessageNumber, MyPop3UniqueID)> for MyPop3UniqueIdListingItem {
    fn into(self) -> (MyPop3MessageNumber, MyPop3UniqueID) {
        self.to_tuple()
    }
}

impl std::fmt::Display for MyPop3UniqueIdListingItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fields = vec![self.message_number.to_string(), self.unique_id.to_string()];
        write!(f, "{}", fields.join(Self::SEPARATOR))
    }
}

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum MyPop3CommandName {
    // https://datatracker.ietf.org/doc/html/rfc1939
    // RFC1939 says:
    //   - "case-insensitive keyword"
    //   - "consist of printable ASCII characters"
    // NOTE: the order of definition below is alphabetical simply.
    APOP,
    DELE,
    LIST,
    NOOP,
    PASS,
    QUIT,
    RETR,
    RSET,
    STAT,
    TOP,
    UIDL,
    USER,
}

impl MyPop3CommandName {
    fn range_of_number_of_arguments(&self) -> RangeInclusive<usize> {
        match self {
            // https://datatracker.ietf.org/doc/html/rfc1939
            Self::APOP => 2..=2,
            Self::DELE => 1..=1,
            Self::LIST => 0..=1, // argument is optional
            Self::NOOP => 0..=0,
            Self::PASS => 1..=1,
            Self::QUIT => 0..=0,
            Self::RETR => 1..=1,
            Self::RSET => 0..=0,
            Self::STAT => 0..=0,
            Self::TOP  => 2..=2,
            Self::UIDL => 0..=1, // argument is optional
            Self::USER => 1..=1,
        }
    }
}

#[test]
#[allow(non_snake_case)]
fn test_001_MyPop3CommandName_from_str() {
    assert_eq!(MyPop3CommandName::LIST, "LIST".parse().unwrap());
    assert_eq!(MyPop3CommandName::LIST, "list".parse().unwrap()); // case-insensitive
    assert_eq!(MyPop3CommandName::LIST, "LiSt".parse().unwrap()); // case-insensitive
    assert!(MyPop3CommandName::from_str(" LIST").is_err()); // an extra space at the start
    assert!(MyPop3CommandName::from_str("LIS T").is_err()); // an extra space in the middle
    assert!(MyPop3CommandName::from_str("LIST ").is_err()); // an extra space at the end
}

//====================================================================
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum MyPop3Command {
    // NOTE: the order of definition below is alphabetical simply.
    APOP(MyPop3Username, MyPop3Digest),
    DELE(MyPop3MessageNumber),
    LIST_ALL,
    LIST_SINGLE(MyPop3MessageNumber),
    NOOP,
    PASS(MyPop3Password),
    QUIT,
    RETR(MyPop3MessageNumber),
    RSET,
    STAT,
    TOP(MyPop3MessageNumber, MyPop3NumberOfLines),
    UIDL_ALL,
    UIDL_SINGLE(MyPop3MessageNumber),
    USER(MyPop3Username),
}

impl std::str::FromStr for MyPop3Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (keyword, args) = validate_and_parse_command_line(s)?;
        let name = MyPop3CommandName::from_str(&keyword).or_else(|e| Err(anyhow!("{:?}\n   where {:?}", e, (&keyword, &args, &s))))?;
        Self::compose(name, &args)
    }
}

impl TryFrom<&[u8]> for MyPop3Command {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let raw_u8 = value;
        match String::from_utf8(Vec::from(raw_u8)) {
            Ok(ss) => Self::from_str(&ss), // delegate
            Err(_) => Err(anyhow!("invalid byte sequence (not UTF-8) in command line: {:?}", raw_u8)),
        }
    }
}

impl MyPop3Command {
    pub fn name(&self) -> MyPop3CommandName {
        let (name, _) = self.decompose();
        name
    }

    pub fn is_multi_line_response_expected(&self) -> bool {
        match &self {
            Self::APOP(_, _)     => false,
            Self::DELE(_)        => false,
            Self::LIST_ALL       => true,
            Self::LIST_SINGLE(_) => false,
            Self::NOOP           => false,
            Self::PASS(_)        => false,
            Self::QUIT           => false,
            Self::RETR(_)        => true,
            Self::RSET           => false,
            Self::STAT           => false,
            Self::TOP(_, _)      => true,
            Self::UIDL_ALL       => true,
            Self::UIDL_SINGLE(_) => false,
            Self::USER(_)        => false,
        }
    }

    pub fn as_message_number(&self) -> Option<&MyPop3MessageNumber> {
        match &self {
            Self::APOP(_, _)     => None,
            Self::DELE(x)        => Some(x),
            Self::LIST_ALL       => None,
            Self::LIST_SINGLE(x) => Some(x),
            Self::NOOP           => None,
            Self::PASS(_)        => None,
            Self::QUIT           => None,
            Self::RETR(x)        => Some(x),
            Self::RSET           => None,
            Self::STAT           => None,
            Self::TOP(x, _)      => Some(x),
            Self::UIDL_ALL       => None,
            Self::UIDL_SINGLE(x) => Some(x),
            Self::USER(_)        => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let (name, args) = self.decompose();
        let mut bin = name.to_string().into_bytes();
        for ss in &args {
            bin.push(b' ');
            bin.extend_from_slice(ss.as_bytes());
        }
        bin.extend_from_slice(b"\r\n");
        bin
    }

    fn compose<T: AsRef<str>, U: AsRef<[T]>>(name: MyPop3CommandName, args: U) -> Result<Self> {
        let args = args.as_ref().iter().map(|s| s.as_ref().to_owned()).collect::<Vec<_>>();
        if !name.range_of_number_of_arguments().contains(&args.len()) {
            return Err(anyhow!("too few/many arguments: {:?}", (name, args)));
        }
        {   // validation
            let dummy_command_line = [name.to_string()].into_iter().chain(args.clone().into_iter()).collect::<Vec<_>>().join(" ");
            let (dummy_keyword, dummy_args) = validate_and_parse_command_line(&dummy_command_line).or_else(|e| Err(anyhow!("{:?}\n   where {:?}", e, (&name, &args))))?;
            assert_eq!(dummy_keyword.to_ascii_uppercase(), name.to_string());
            assert_eq!(dummy_args, args);
        }
        let typed_command = match (name, args.len()) {
            (MyPop3CommandName::APOP, 2) => Self::APOP(args[0].parse()?, args[1].parse()?),
            (MyPop3CommandName::DELE, 1) => Self::DELE(args[0].parse()?),
            (MyPop3CommandName::LIST, 0) => Self::LIST_ALL,
            (MyPop3CommandName::LIST, 1) => Self::LIST_SINGLE(args[0].parse()?),
            (MyPop3CommandName::NOOP, 0) => Self::NOOP,
            (MyPop3CommandName::PASS, 1) => Self::PASS(args[0].parse()?),
            (MyPop3CommandName::QUIT, 0) => Self::QUIT,
            (MyPop3CommandName::RETR, 1) => Self::RETR(args[0].parse()?),
            (MyPop3CommandName::RSET, 0) => Self::RSET,
            (MyPop3CommandName::STAT, 0) => Self::STAT,
            (MyPop3CommandName::TOP,  2) => Self::TOP(args[0].parse()?, args[1].parse()?),
            (MyPop3CommandName::UIDL, 0) => Self::UIDL_ALL,
            (MyPop3CommandName::UIDL, 1) => Self::UIDL_SINGLE(args[0].parse()?),
            (MyPop3CommandName::USER, 1) => Self::USER(args[0].parse()?),

            (MyPop3CommandName::APOP, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::DELE, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::LIST, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::NOOP, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::PASS, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::QUIT, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::RETR, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::RSET, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::STAT, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::TOP,  _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::UIDL, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::USER, _) => unreachable!("{:?}", (name, args)),
        };

        if true { // for debug
            let (name2, args2) = typed_command.decompose();
            assert_eq!(name2, name);
            assert_eq!(args2.len(), args.len());
            for i in 0..args2.len() {
                assert_eq!(args2[i], args[i]);
            }
        }

        Ok(typed_command)
    }

    fn decompose(&self) -> (MyPop3CommandName, Vec<String>) {
        let (name, args): (MyPop3CommandName, &[&dyn std::fmt::Display]) = match &self {
            Self::APOP(x, y) => (MyPop3CommandName::APOP, &[x, y]),
            Self::DELE(x) => (MyPop3CommandName::DELE, &[x]),
            Self::LIST_ALL => (MyPop3CommandName::LIST, &[]),
            Self::LIST_SINGLE(x) => (MyPop3CommandName::LIST, &[x]),
            Self::NOOP => (MyPop3CommandName::NOOP, &[]),
            Self::PASS(x) => (MyPop3CommandName::PASS, &[x]),
            Self::QUIT => (MyPop3CommandName::QUIT, &[]),
            Self::RETR(x) => (MyPop3CommandName::RETR, &[x]),
            Self::RSET => (MyPop3CommandName::RSET, &[]),
            Self::STAT => (MyPop3CommandName::STAT, &[]),
            Self::TOP(x, y) => (MyPop3CommandName::TOP, &[x, y]),
            Self::UIDL_ALL => (MyPop3CommandName::UIDL, &[]),
            Self::UIDL_SINGLE(x) => (MyPop3CommandName::UIDL, &[x]),
            Self::USER(x) => (MyPop3CommandName::USER, &[x]),
        };
        let args: Vec<_> = args.into_iter().map(|s| s.to_string()).collect();
        (name, args)
    }
}

fn validate_and_parse_command_line(s: &str) -> Result<(String, Vec<String>)> {
    // RFC1939 says:
    //   - Commands in the POP3 consist of a case-insensitive keyword, possibly followed by one or more arguments.
    //   - All commands are terminated by a CRLF pair.
    //   - Keywords and arguments consist of printable ASCII characters.
    //   - Keywords and arguments are each separated by a single SPACE character.
    //   - Keywords are three or four characters long.
    //   - Each argument may be up to 40 characters long.
    let s = s.strip_suffix("\r\n").unwrap_or(s); // for convenience, allow a string without CRLF
    if s.is_empty() {
        return Err(anyhow!("command line is empty"));
    }
    let separator = ' '; // single SPACE character
    let mut it = s.split(separator).map(|s| s.to_string());
    let keyword = it.next().ok_or_else(|| anyhow!("no keyword: {:?}", s))?;
    let args = it.collect::<Vec<_>>();

    let validator = |ss: &str, range_of_length: &RangeInclusive<usize>| {
        if ss.is_empty() {
            return Err(anyhow!("empty field (continuous SPACE characters is not allowed): {:?}", (ss, &keyword, &args, s)));
        }
        if !range_of_length.contains(&ss.len()) {
            return Err(anyhow!("invalid length of a field: {:?}", (ss.len(), &ss, &keyword, &args, s)));
        }
        if !ss.chars().all(|c| c.is_ascii_printable()) {
            return Err(anyhow!("invalid character in a field: {:?}", (ss, &keyword, &args, ss)));
        }
        Ok(())
    };
    let range_of_length_of_keyword: RangeInclusive<usize> = 3..=4;
    let range_of_length_of_argument: RangeInclusive<usize> = 1..=40;

    let _ = validator(&keyword, &range_of_length_of_keyword)?;
    for arg in &args {
        let _ = validator(&arg, &range_of_length_of_argument)?;
    }

    Ok((keyword, args))
}

#[test]
fn test_001_validate_and_parse_command_line() {
    fn should_be_eq(input_text: &str, expected: &[&str]) {
        let (keyword, args) = validate_and_parse_command_line(input_text).unwrap();
        let left = [vec![keyword], args].concat();
        let right = expected.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(left, right, "{:?}", (&input_text, &expected));
    }
    fn should_be_err(input_text: &str) {
        assert!(validate_and_parse_command_line(input_text).is_err(), "{:?}", (&input_text));
    }

    should_be_eq("ABC", &["ABC"]);
    should_be_eq("ABC\r\n", &["ABC"]);
    should_be_eq("aBc", &["aBc"]);
    should_be_eq("abcd", &["abcd"]);
    should_be_eq("aBc9", &["aBc9"]);
    should_be_eq("ABC 123", &["ABC", "123"]);
    should_be_eq("ABC 123 4 !@_+", &["ABC", "123", "4", "!@_+"]);
    should_be_eq("ABC 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15", &["ABC", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"]);
    should_be_eq("ABC 1111222233334444555566667777888899990000", &["ABC", "1111222233334444555566667777888899990000"]);
    should_be_eq("ABC 1111222233334444555566667777888899990000\r\n", &["ABC", "1111222233334444555566667777888899990000"]);

    should_be_err("");
    should_be_err("\r\n");
    should_be_err("\r\n\r\n");
    should_be_err("\r\n ");
    should_be_err("\r\na");

    should_be_err(" ");
    should_be_err(" \r\n");
    should_be_err(" \r\n\r\n");
    should_be_err(" \r\n ");
    should_be_err(" \r\na");

    should_be_err(" ABC");
    should_be_err(" ABC\r\n");
    should_be_err(" ABC\r\n ");
    should_be_err("AB C");
    should_be_err("AB C\r\n");
    should_be_err("AB C\r\n ");
    should_be_err("ABC ");
    should_be_err("ABC \r\n");
    should_be_err("ABC\r\n ");

    should_be_err(" ABC 123\r\n");
    should_be_err("ABC  123\r\n");
    should_be_err("ABC 123 \r\n");
    should_be_err("ABC 123\r\n ");

    should_be_err(" ABC 123 4 5\r\n"); // an extra SPACE at the start
    should_be_err("ABC 123  4 5\r\n"); // muliple SPACEs
    should_be_err("ABC 123 4  5\r\n"); // multiple SPACEs
    should_be_err("ABC 123 4 5 \r\n"); // an extra SPACE at the end
    should_be_err("ABC 123 4 5\r\n "); // an extra SPACE at next of CRLF

    should_be_err("\tABC"); // TAB is not allowed
    should_be_err("A\tBC"); // TAB is not allowed
    should_be_err("AB\ttC"); // TAB is not allowed
    should_be_err("ABC\t"); // TAB is not allowed
    should_be_err("ABC\t\r\n"); // TAB is not allowed
    should_be_err("ABC\r\n\t"); // TAB is not allowed

    should_be_err("ABC "); // an extra SPACE at the end
    should_be_err("ABC \r\n"); // an extra SPACE at the end
    should_be_err("ABC\r\n "); // an extra SPACE at next of CRLF
    should_be_err("ABC  "); // multiple extra SPACEs at the end
    should_be_err("ABC  \r\n"); // multiple extra SPACEs at the end

    should_be_err("A\r\n");
    should_be_err("AB\r\n");
    should_be_err("ABCDE\r\n");
    should_be_err("1111222233334444555566667777888899990000\r\n");

    should_be_err("ABC 1111222233334444555566667777888899990000+");
    should_be_err("ABC 1111222233334444555566667777888899990000 1111222233334444555566667777888899990000+ 1111222233334444555566667777888899990000");
}

//====================================================================
#[derive(Debug, PartialEq, Eq)]
pub enum MyPop3Response {
    OkSingleLine {
        status_line: MyPop3StatusLine,
    },
    OkMultiLine {
        status_line: MyPop3StatusLine,
        contents: MyPop3Contents,
    },
    Err {
        status_line: MyPop3StatusLine,
    },
}

impl TryFrom<&[u8]> for MyPop3Response {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let raw_u8 = Vec::from(value);
        if raw_u8.is_empty() {
            return Err(anyhow!("invalid POP3 response: should not be empty"));
        }
        if !raw_u8.ends_with(LINE_TERMINATOR.as_bytes()) {
            return Err(anyhow!("invalid POP3 response: should be ended with CRLF: {:?}", raw_u8));
        }
        let status_line = MyPop3StatusLine::from_str(&take_first_line(&raw_u8)?)?;
        let offset = status_line.as_str().as_bytes().len() + LINE_TERMINATOR.as_bytes().len();
        let is_multi_line_response = offset < raw_u8.len();
        let obj = match (status_line.is_ok(), is_multi_line_response) {
            (false, false) => Self::Err { status_line },
            (false, true) => return Err(anyhow!("invalid POP3 response (ERR response should be single-line response): {:?}", raw_u8)),
            (true, false) => Self::OkSingleLine { status_line },
            (true, true) => {
                assert!(raw_u8[..offset].ends_with(LINE_TERMINATOR.as_bytes())); // bytes immediately before the offset should be CRLF
                let contents = MyPop3Contents::decode_from_response(&raw_u8[offset..])?;
                Self::OkMultiLine { status_line, contents }
            },
        };
        assert_eq!(obj.is_ok(), obj.as_status_line().is_ok());
        assert!(!obj.is_multi_line_response() || obj.is_ok());
        assert_eq!(obj.is_multi_line_response(), obj.as_contents().is_some());
        Ok(obj)
    }
}

impl MyPop3Response {
    // static utility function (to encapsulate the pattern "+OK")
    pub fn is_likely_to_be_ok(ss: &str) -> bool {
        MyPop3StatusLine::is_likely_to_be_ok(ss)
    }

    // static utility function (to encapsulate the pattern "-ERR")
    pub fn is_likely_to_be_err(ss: &str) -> bool {
        MyPop3StatusLine::is_likely_to_be_err(ss)
    }

    pub fn is_ok(&self) -> bool {
        match self {
            Self::OkSingleLine { .. } => true,
            Self::OkMultiLine { .. } => true,
            Self::Err { .. } => false,
        }
    }

    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    pub fn is_multi_line_response(&self) -> bool {
        match self {
            Self::OkSingleLine { .. } => false,
            Self::OkMultiLine { .. } => true,
            Self::Err { .. } => false,
        }
    }

    pub fn as_status_line(&self) -> &MyPop3StatusLine {
        match &self {
            Self::OkSingleLine { status_line, .. } => status_line,
            Self::OkMultiLine { status_line, .. } => status_line,
            Self::Err { status_line, .. } => status_line,
        }
    }

    pub fn as_contents(&self) -> Option<&MyPop3Contents> {
        match self {
            Self::OkSingleLine { .. } => None,
            Self::OkMultiLine { contents, .. } => Some(contents),
            Self::Err { .. } => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        make_raw_response_u8(self.as_status_line(), self.as_contents())
    }

    //====================
    pub fn rebuild(&self, new_status_line: &MyPop3StatusLine, new_contents: Option<&MyPop3Contents>) -> Self {
        assert_eq!(self.is_ok(), new_status_line.is_ok());
        assert_eq!(self.is_multi_line_response(), new_contents.is_some()); // may be an empty slice
        let bin = make_raw_response_u8(new_status_line, new_contents);
        Self::try_from(bin.as_ref()).unwrap()
    }

    pub fn rebuild_with_new_lines(&self, new_status_line: &MyPop3StatusLine, new_lines: impl Iterator<Item = impl ToString>) -> Self {
        let new_contents = MyPop3Contents::from_items(new_lines);
        self.rebuild(new_status_line, Some(&new_contents))
    }

    //====================
    pub fn parse_as_for_list_all(&self, command: &MyPop3Command) -> Result<(Option<MyPop3NumberOfMessages>, Option<MyPop3Octets>, Vec<MyPop3ScanListingItem>)> {
        assert!(self.is_ok() && self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::LIST && command.is_multi_line_response_expected(), "{:?}", (&self, &command));

        let (total_count, total_nbytes) = self.as_status_line().parse_as_for_list_all().unwrap_or_default(); // ignore errors
        let contents: Vec<MyPop3ScanListingItem> = self.as_contents().unwrap().to_items()?;

        if let Some(total_count) = &total_count {
            let calculated_count = contents.len();
            if calculated_count != total_count.as_usize() {
                warn!("number of lines of contents does not match with the value in status line of LIST_ALL command: {:?}", (calculated_count, &total_count, &self, &command));
            }
        }
        if let Some(total_nbytes) = &total_nbytes {
            let calculated_nbytes = contents.iter().map(|item| item.as_nbytes().as_usize()).sum::<usize>();
            if calculated_nbytes != total_nbytes.as_usize() {
                warn!("sum of contents does not match with the value in status line of LIST_ALL command: {:?}", (calculated_nbytes, &total_nbytes, &self, &command));
            }
        }

        Ok((total_count, total_nbytes, contents))
    }

    pub fn parse_as_for_list_single(&self, command: &MyPop3Command) -> Result<MyPop3ScanListingItem> {
        assert!(self.is_ok() && !self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::LIST && !command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        self.as_status_line().parse_as_for_list_single()
    }

    pub fn parse_as_for_retr(&self, command: &MyPop3Command) -> Result<(Option<usize>, Vec<u8>)> {
        assert!(self.is_ok() && self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::RETR || command.name() == MyPop3CommandName::TOP, "{:?}", (&self, &command));
        assert!(command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        let arg_nbytes = self.as_status_line().parse_as_for_retr()?;
        let contents_u8 = self.as_contents().unwrap().as_contents_u8().to_owned();

        if arg_nbytes.is_some() && arg_nbytes.clone().unwrap().as_usize() != contents_u8.len() {
            warn!("the argument does not match with the size of contents: {:?}", (&arg_nbytes, contents_u8.len(), self.as_status_line()));
        }
        let arg_nbytes = arg_nbytes.map(|x| x.as_usize());
        Ok((arg_nbytes, contents_u8))
    }

    pub fn parse_as_for_stat(&self, command: &MyPop3Command) -> Result<(MyPop3NumberOfMessages, MyPop3Octets)> {
        assert!(self.is_ok() && !self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::STAT && !command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        self.as_status_line().parse_as_for_stat()
    }

    pub fn parse_as_for_top(&self, command: &MyPop3Command) -> Result<(Option<usize>, Vec<u8>)> {
        #![allow(unused)]
        unimplemented!()
    }

    pub fn parse_as_for_uidl_all(&self, command: &MyPop3Command) -> Result<Vec<MyPop3UniqueIdListingItem>> {
        assert!(self.is_ok() && self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::UIDL && command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        self.as_contents().unwrap().to_items()
    }

    pub fn parse_as_for_uidl_single(&self, command: &MyPop3Command) -> Result<MyPop3UniqueIdListingItem> {
        #![allow(unused)]
        assert!(self.is_ok() && !self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::UIDL && !command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        self.as_status_line().parse_as_for_uidl_single()
    }

    //====================
    pub fn rebuild_as_for_list_all(&self, new_list: &[MyPop3ScanListingItem], command: &MyPop3Command) -> Self {
        assert!(self.is_ok() && self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::LIST && command.is_multi_line_response_expected(), "{:?}", (&self, &command));

        let (_, _, original_list) = self.parse_as_for_list_all(&command).unwrap();
        if new_list.len() != original_list.len() {
            warn!("length of modified contents for LIST_ALL is different from original: {:?}", (new_list.len(), original_list.len(), &self, &command));
        }

        let total_count = new_list.len().into();
        let total_nbytes = new_list.iter().map(|item| item.as_nbytes().as_usize()).sum::<usize>().into();
        let new_status_line = self.as_status_line().rebuild_as_for_list_all(&total_count, &total_nbytes);
        let new_response = self.rebuild_with_new_lines(&new_status_line, new_list.iter());
        assert_eq!(new_list, new_response.parse_as_for_list_all(&command).unwrap().2, "{:?}", (&new_response, &self, &new_list, &command));
        new_response
    }

    pub fn rebuild_as_for_list_single(&self, item: &MyPop3ScanListingItem, command: &MyPop3Command) -> Self {
        assert!(self.is_ok() && !self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::LIST && !command.is_multi_line_response_expected(), "{:?}", (&self, &command));

        let original_item = self.parse_as_for_list_single(&command).unwrap();
        assert_eq!(item.as_message_number(), original_item.as_message_number(), "{:?}", (&original_item, &item, &self, &command));

        let new_status_line = self.as_status_line().rebuild_as_for_list_single(item.as_message_number(), item.as_nbytes());
        let new_response = self.rebuild(&new_status_line, None);
        assert_eq!(item, &new_response.parse_as_for_list_single(&command).unwrap(), "{:?}", (&new_response, &self, &item, &command));
        new_response
    }

    pub fn rebuild_as_for_retr(&self, contents: &[u8], command: &MyPop3Command) -> Self {
        assert!(self.is_ok() && self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::RETR || command.name() == MyPop3CommandName::TOP, "{:?}", (&self, &command));
        assert!(command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        assert!(contents.is_empty() || contents.ends_with(b"\r\n"), "{:?}", (contents.len(), &contents[(contents.len().max(8) - 8)..], &self, &command));
        let _ = self.parse_as_for_retr(&command).unwrap(); // validation (just in case)

        let new_nbytes: MyPop3Octets = contents.len().into();
        let new_status_line = self.as_status_line().rebuild_as_for_retr(&new_nbytes);
        let new_contents = MyPop3Contents::from_bytes(contents.iter().cloned()).unwrap();
        let new_response = self.rebuild(&new_status_line, Some(&new_contents));
        assert_eq!(contents, new_response.parse_as_for_retr(&command).unwrap().1, "{:?}", (&new_response, &self, &command));
        new_response
    }

    pub fn rebuild_as_for_stat(&self, total_count: &MyPop3NumberOfMessages, total_nbytes: &MyPop3Octets, command: &MyPop3Command) -> Self {
        assert!(self.is_ok() && !self.is_multi_line_response(), "{:?}", (&self, &command));
        assert!(command.name() == MyPop3CommandName::STAT && !command.is_multi_line_response_expected(), "{:?}", (&self, &command));
        let _ = self.parse_as_for_stat(&command).unwrap(); // validation (just in case)

        let new_status_line = self.as_status_line().rebuild_as_for_stat(&total_count, &total_nbytes);
        let new_response = self.rebuild(&new_status_line, None);
        assert_eq!((total_count.clone(), total_nbytes.clone()), new_response.parse_as_for_stat(&command).unwrap());
        new_response
    }

    pub fn rebuild_as_for_top(&self, new_contents: &[u8], command: &MyPop3Command) -> Self {
        #![allow(unused)]
        unimplemented!()
    }

    pub fn rebuild_as_for_uidl_all(&self, new_list: &[(MyPop3MessageNumber, MyPop3UniqueID)], command: &MyPop3Command) -> Self {
        #![allow(unused)]
        unimplemented!()
    }

    pub fn rebuild_as_for_uidl_single(&self, message_number: &MyPop3MessageNumber, unique_id: &MyPop3UniqueID, command: &MyPop3Command) -> Self {
        #![allow(unused)]
        unimplemented!()
    }
}

//====================
fn make_raw_response_u8(status_line: &MyPop3StatusLine, contents: Option<&MyPop3Contents>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(status_line.as_str().trim_end_matches("\r\n").as_bytes());
    buf.extend_from_slice(LINE_TERMINATOR.as_bytes());
    if let Some(contents) = contents {
        // contents may be empty
        let contents = contents.encode_as_rest_of_response(); // include escaping period-only lines (termination octet)
        assert!(contents.is_empty() || contents.ends_with(LINE_TERMINATOR.as_bytes()));
        buf.extend_from_slice(&contents);
        buf.extend_from_slice(TERMINATOR_OF_CONTENTS_OF_RESPONSE.as_bytes());
    }
    buf
}

//====================
#[test]
#[allow(non_snake_case)]
fn test_001_MyPop3Response_try_from() {
    let status_line = "+OK";
    let raw_u8 = format!("{}\r\n", status_line).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_ok() && !response.is_multi_line_response() && response.as_status_line().as_str() == status_line);

    let status_line = "+OK 123";
    let raw_u8 = format!("{}\r\n", status_line).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_ok() && !response.is_multi_line_response() && response.as_status_line().as_str() == status_line);

    let status_line = "-ERR";
    let raw_u8 = format!("{}\r\n", status_line).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_err() && !response.is_multi_line_response() && response.as_status_line().as_str() == status_line);

    let status_line = "-ERR foo bar";
    let raw_u8 = format!("{}\r\n", status_line).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_err() && !response.is_multi_line_response() && response.as_status_line().as_str() == status_line);

    // multi-line response with empty contents
    let status_line = "+OK";
    let contents_u8 = b"";
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(contents_u8)).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_ok() && response.is_multi_line_response() && response.as_status_line().as_str() == status_line);
    assert_eq!(response.as_contents().unwrap().as_contents_u8(), contents_u8.as_ref());

    // multi-line response with contents of one line
    let status_line = "+OK";
    let contents_u8 = b"foo bar\r\n";
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(contents_u8)).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_ok() && response.is_multi_line_response() && response.as_status_line().as_str() == status_line);
    assert_eq!(response.as_contents().unwrap().as_contents_u8(), contents_u8.as_ref());

    // multi-line response with contents of three lines
    let status_line = "+OK";
    let contents_u8 = b"foo bar\r\n\r\nbuz\r\n";
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(contents_u8)).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_ok() && response.is_multi_line_response() && response.as_status_line().as_str() == status_line);
    assert_eq!(response.as_contents().unwrap().as_contents_u8(), contents_u8.as_ref());

    // ERR response can not have contents
    let status_line = "-ERR";
    let raw_u8 = format!("{}\r\n", status_line).into_bytes();
    let response = MyPop3Response::try_from(raw_u8.as_ref()).unwrap();
    assert!(response.is_err() && !response.is_multi_line_response() && response.as_status_line().as_str() == status_line);
}

//====================================================================
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyPop3Contents {
    // NOTE: hold `Vec<u8>` rather than `String` because there are some responses which do NOT require the convertion to `String`.
    contents_u8: Vec<u8>,
}

impl MyPop3Contents {
    fn from_bytes(it: impl Iterator<Item = u8>) -> Result<Self> {
        let bin = Vec::from_iter(it);
        if !bin.is_empty() && !bin.ends_with(LINE_TERMINATOR.as_bytes()) {
            return Err(anyhow!("invalid contents: {:?}", (&bin)));
        }
        Ok(Self {
            contents_u8: bin,
        })
    }

    pub fn from_lines(it: impl Iterator<Item = String>) -> Self {
        // each lines may contain CRLF at the end
        let it = it.map(|ss| ss.as_bytes().my_trim_suffix(&LINE_TERMINATOR.as_bytes()).to_vec());
        let it = it.flat_map(|arr| arr.into_iter().chain(LINE_TERMINATOR.bytes()));
        Self::from_bytes(it).unwrap()
    }

    pub fn from_items<T: ToString>(it: impl Iterator<Item = T>) -> Self {
        let it = it.map(|x| x.to_string());
        Self::from_lines(it)
    }

    pub fn decode_from_response(raw_u8: &[u8]) -> Result<Self> {
        if raw_u8.len() < TERMINATOR_OF_CONTENTS_OF_RESPONSE.len() {
            return Err(anyhow!("invalid POP3 response: contents of multi-line response is too short: {:?}", (raw_u8.len())));
        }
        let nbytes = raw_u8.len() - TERMINATOR_OF_CONTENTS_OF_RESPONSE.len(); // may be zero
        let tail = &raw_u8[nbytes..];
        if tail != TERMINATOR_OF_CONTENTS_OF_RESPONSE.as_bytes() {
            return Err(anyhow!("invalid POP3 response: multi-line response should be ends with {:?}, but {:?}", &*TERMINATOR_OF_CONTENTS_OF_RESPONSE, &tail));
        }

        let bin = &raw_u8[..nbytes];
        let bin = Self::unescape_termination_octet(&bin);
        Self::from_bytes(bin.iter().cloned())
    }

    pub fn encode_as_rest_of_response(&self) -> Vec<u8> {
        let mut v = Self::escape_termination_octet(&self.as_contents_u8());
        v.extend_from_slice(TERMINATOR_OF_CONTENTS_OF_RESPONSE.as_bytes());
        v
    }

    pub fn as_contents_u8(&self) -> &[u8] {
        &self.contents_u8
    }

    pub fn to_text(&self) -> Result<String> {
        let bin = self.as_contents_u8().to_vec();
        assert!(bin.is_empty() || bin.ends_with(LINE_TERMINATOR.as_bytes()));
        let text = String::from_utf8(bin).map_err(|_| anyhow!("not UTF-8 string"))?;
        Ok(text)
    }

    pub fn to_lines(&self) -> Result<Vec<String>> { // CRLF is NOT included
        let ss = self.to_text()?;
        let v = if ss.is_empty() {
            Vec::new()
        } else {
            assert!(ss.ends_with(&*LINE_TERMINATOR));
            ss.split_terminator(&*LINE_TERMINATOR).map(|ss| ss.to_string()).collect::<Vec<_>>()
        };
        Ok(v)
    }

    pub fn to_items<T: FromStr<Err = anyhow::Error>>(&self) -> Result<Vec<T>> {
        let it = self.to_lines()?;
        let v = it.into_iter().map(|ss| T::from_str(&ss)).collect::<Result<Vec<_>>>()?; // convert "a sequence of Result" into "Result of a sequence"
        Ok(v)
    }

    //====================
    // in RFC1939, ".\r\n" (a termination octet and a CRLF pair) has special meaning as the terminator of a multi-line response.
    // So it is necessary to escape/unescape period-only lines in a multi-line response.
    fn escape_termination_octet(bin: &[u8]) -> Vec<u8> {
        // TODO: implement to escape period-only lines as described in "Secton 3. Basic Operation" in RFC1939
        warn!("escape_termination_octet() is not implemented yet");
        let _termination_octet = TERMINATOR_OF_CONTENTS_OF_RESPONSE.as_bytes()[0];
        bin.to_vec()
    }

    // helper function
    fn unescape_termination_octet(bin: &[u8]) -> Vec<u8> {
        // TODO: implement to restore period-only lines as described in "Secton 3. Basic Operation" in RFC1939
        warn!("unescape_termination_octet() is not implemented yet");
        let _termination_octet = TERMINATOR_OF_CONTENTS_OF_RESPONSE.as_bytes()[0];
        bin.to_vec()
    }
}

#[test]
#[allow(non_snake_case)]
fn test_001_MyPop3Contents_decode_from_response() {
    assert_eq!(b"", MyPop3Contents::decode_from_response(b".\r\n").unwrap().as_contents_u8()); // empty
    assert_eq!(b"\r\n", MyPop3Contents::decode_from_response(b"\r\n.\r\n").unwrap().as_contents_u8()); // one empty line
    assert_eq!(b"a\r\n", MyPop3Contents::decode_from_response(b"a\r\n.\r\n").unwrap().as_contents_u8()); // one normal line
    assert_eq!(b"a b c\r\n", MyPop3Contents::decode_from_response(b"a b c\r\n.\r\n").unwrap().as_contents_u8());
    assert_eq!(b"a b c\r\n\r\nd e f\r\n\r\n", MyPop3Contents::decode_from_response(b"a b c\r\n\r\nd e f\r\n\r\n.\r\n").unwrap().as_contents_u8());

    assert!(MyPop3Contents::decode_from_response(b"\r\n").is_err());
}

//====================================================================
// RFC1939 says "followed by a single space", but accept any ASCII whitespaces as a separator.
// This is based on the concept of Postel's Law: "Be conservative in what you do, be liberal in what you accept from others."
// When modify it, keep original separator as possible (not fix it even if it is incorrect).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyPop3StatusLine {
    raw_line: String, // include indicator (`+OK` or `-ERR`), but not include CRLF
    indicator: MyPop3Indicator,
    fields: Vec<MyAsciiParsedField>,
}

impl FromStr for MyPop3StatusLine {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("invalid POP3 response: empty status line: {:?}", (&s)));
        }
        let ss = s.split_terminator(&*LINE_TERMINATOR).nth(0).unwrap(); // allow CRLF and the following lines (ignored)
        let s = (); // just in case, invalidate this variable
        if ss.is_empty() {
            return Err(anyhow!("invalid POP3 response: empty status line: {:?}", (&s)));
        }
        if ss.len() + "\r\n".len() > 512 {
            // RFC1939 says `Responses may be up to 512 characters long, including the terminating CRLF`
            return Err(anyhow!("invalid POP3 response line: too long: {:?}", (&ss)));
        }
        if !ss.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) { // allow SPACE character, but TAB and other whitespaces are NOT allowed
            return Err(anyhow!("invalid codepoint: {:?}", (&ss)));
        }
        let fields = MyAsciiParsedField::parse(&ss, Self::is_separator)?;
        fields.try_into()
    }
}

impl TryFrom<Vec<MyAsciiParsedField>> for MyPop3StatusLine {
    type Error = anyhow::Error;

    fn try_from(value: Vec<MyAsciiParsedField>) -> std::result::Result<Self, Self::Error> {
        let fields = value;
        assert!(!fields.is_empty());
        if fields[0].is_separator() {
            return Err(anyhow!("any extra whitespace before the indicator are not allowed: {:?}", (&fields)));
        }
        let raw_line = fields.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("");
        let indicator = fields[0].as_str().try_into()?;
        Ok(Self {
            raw_line,
            indicator,
            fields,
        })
    }
}

impl TryFrom<&[MyAsciiParsedField]> for MyPop3StatusLine {
    type Error = anyhow::Error;

    fn try_from(value: &[MyAsciiParsedField]) -> std::result::Result<Self, Self::Error> {
        let fields = Vec::from(value);
        fields.try_into()
    }
}

impl std::fmt::Display for MyPop3StatusLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for MyPop3StatusLine {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl MyPop3StatusLine {
    // static utility function (to encapsulate the pattern "+OK")
    pub fn is_likely_to_be_ok(ss: &str) -> bool {
        assert!(!ss.is_empty());
        MyPop3Indicator::from_str(ss).map_or(false, |x| x.is_ok())
    }

    // static utility function (to encapsulate the pattern "-ERR")
    pub fn is_likely_to_be_err(ss: &str) -> bool {
        assert!(!ss.is_empty());
        MyPop3Indicator::from_str(ss).map_or(false, |x| x.is_err())
    }

    // static helper function (to encapsulate the condition of separator)
    fn is_separator(c: char) -> bool {
        !c.is_ascii_printable()
    }

    // getter
    pub fn as_str(&self) -> &str {
        &self.raw_line
    }

    pub fn as_rest_of_line(&self) -> &str {
        // 1st argument and the following text (if exists)
        let it = self.fields.iter().take(2); // skip the indicator `+OK` and the following spaces
        let offset = it.map(|x| x.as_str().len()).sum::<usize>();
        assert_eq!(offset < self.raw_line.len(), self.fields.len() > 2);
        self.raw_line.get(offset..).unwrap_or("")
    }

    pub fn to_args(&self) -> Vec<String> {
        self.fields.iter().skip(1).filter(|x| !x.is_separator()).map(|x| x.as_str().to_string()).collect()
    }

    pub fn is_ok(&self) -> bool {
        self.indicator.is_ok()
    }

    #[allow(unused)]
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    //====================
    fn rebuild_with_args<T: AsRef<str>>(&self, new_args: &[T]) -> Self {
        let new_args = new_args.into_iter().map(|ss| {
            let ss = ss.as_ref().to_string();
            let v = MyAsciiParsedField::parse(&ss, Self::is_separator).unwrap();
            assert_eq!(v.len(), 1);
            v.into_iter().nth(0).unwrap()
        }).collect::<Vec<_>>();
        let original_chunks = self.fields.chunks(2).collect::<Vec<_>>();
        assert!(new_args.len() <= original_chunks.len() - 1); // first chunk is the indicator, not an argument

        let new_fields = original_chunks.into_iter().enumerate().flat_map(|(index, chunk)| {
            let mut chunk = chunk.into_iter().map(|x| x.clone()).collect::<Vec<_>>();
            if index > 0 {
                if let Some(new_value) = new_args.get(index - 1) {
                    chunk[0] = new_value.clone(); // replace if the corresponding value exists in `new_args`
                }
            }
            chunk.into_iter()
        }).collect::<Vec<_>>();

        new_fields.try_into().unwrap()
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test_MyPop3StatusLine {
    use std::str::FromStr;
    use super::MyPop3StatusLine;
    type TestTarget = MyPop3StatusLine;

    #[test]
    #[allow(non_snake_case)]
    fn test_100_MyPop3StatusLine_err() {
        assert!(TestTarget::from_str("").is_err()); // empty
        assert!(TestTarget::from_str("\r\n").is_err()); // empty
        assert!(TestTarget::from_str("\r\n+OK\r\n").is_err()); // empty
        assert!(TestTarget::from_str(" ").is_err());
        assert!(TestTarget::from_str("\r").is_err());
        assert!(TestTarget::from_str("\n").is_err());
        assert!(TestTarget::from_str("\t").is_err());
        assert!(TestTarget::from_str("\0").is_err()); // NUL
        assert!(TestTarget::from_str("あ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("＋OK").is_err()); // non-ASCII
        assert!(TestTarget::from_str("+OＫ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("＋ＯＫ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("－ERR").is_err()); // non-ASCII
        assert!(TestTarget::from_str("-ERＲ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("－ＥＲＲ").is_err()); // non-ASCII
        assert!(TestTarget::from_str(" \r\n").is_err());
        assert!(TestTarget::from_str(" +OK").is_err());
        assert!(TestTarget::from_str("a").is_err());
        assert!(TestTarget::from_str("+").is_err());
        assert!(TestTarget::from_str("+O").is_err());
        assert!(TestTarget::from_str("+ok").is_err());
        assert!(TestTarget::from_str("+OKK").is_err());
        assert!(TestTarget::from_str("+OK\r").is_err()); // CR without LF
        assert!(TestTarget::from_str("+OK\n").is_err()); // LF without CR
        assert!(TestTarget::from_str("+OK\0").is_err()); // NUL
        assert!(TestTarget::from_str("+OKあ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("+OK あ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("+OK aあ").is_err()); // non-ASCII
        assert!(TestTarget::from_str("+OK あb").is_err()); // non-ASCII
        assert!(TestTarget::from_str("+OK aあb").is_err()); // non-ASCII
        assert!(TestTarget::from_str("+OK \0").is_err()); // NUL
        assert!(TestTarget::from_str("+OK a\0").is_err()); // NUL
        assert!(TestTarget::from_str("+OK \0b").is_err()); // NUL
        assert!(TestTarget::from_str("+OK a\0b").is_err()); // NUL
        assert!(TestTarget::from_str("+OK a \0").is_err()); // NUL
        assert!(TestTarget::from_str("+OK \0 b").is_err()); // NUL
        assert!(TestTarget::from_str("+OK a \0 b").is_err()); // NUL
        assert!(TestTarget::from_str("-").is_err());
        assert!(TestTarget::from_str("-E").is_err());
        assert!(TestTarget::from_str("-ER").is_err());
        assert!(TestTarget::from_str("-err").is_err());
        assert!(TestTarget::from_str("-ERRR").is_err());
        assert!(TestTarget::from_str("-ERR\r").is_err()); // CR without LF
        assert!(TestTarget::from_str("-ERR\n").is_err()); // LF without CR
        assert!(TestTarget::from_str("-ERR\0").is_err()); // NUL
        assert!(TestTarget::from_str("-ERRあ").is_err()); // non-ASCII
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_101_MyPop3StatusLine_constructor() {
        fn checker(num_of_args: usize, ss: &str) {
            assert!(ss.starts_with("+OK"), "{:?}", (&ss)); // check test pattern itself
            let x = TestTarget::from_str(&ss).unwrap();
            assert!(x.is_ok(), "{:?}", (&x, &ss));
            assert_eq!(num_of_args, x.to_args().len(), "{:?}", (&x, &ss));
            let ss = "-ERR".to_string() + &ss["+OK".len()..];
            let x = TestTarget::from_str(&ss).unwrap();
            assert!(x.is_err(), "{:?}", (&x, &ss));
            assert_eq!(num_of_args, x.to_args().len(), "{:?}", (&x, &ss));
        }

        checker(0, "+OK");
        checker(0, "+OK ");
        checker(0, "+OK  ");
        checker(0, "+OK        ");
        checker(0, "+OK\r\n");
        checker(0, "+OK\r\nabc"); // with the following lines
        checker(0, "+OK\r\n "); // with the following lines
        checker(0, "+OK\r\n\0"); // with the following lines which include NUL
        checker(0, "+OK\r\n\r"); // with the following lines which include CR only
        checker(0, "+OK\r\n\n"); // with the following lines which include LF only
        checker(0, "+OK\r\nあ"); // with the following lines which include non-ASCII

        checker(0, "+OK\r\n\r\n"); // with the following lines
        checker(0, "+OK\r\nabc\r\n"); // with the following lines
        checker(0, "+OK\r\n \r\n"); // with the following lines
        checker(0, "+OK\r\n\0\r\n"); // with the following lines which include NUL
        checker(0, "+OK\r\n\r\r\n"); // with the following lines which include CR only
        checker(0, "+OK\r\n\n\r\n"); // with the following lines which include LF only
        checker(0, "+OK\r\nあ\r\n"); // with the following lines which include non-ASCII

        checker(1, "+OK 1");
        checker(1, "+OK 1 ");
        checker(1, "+OK  1");
        checker(1, "+OK        1");
        checker(1, "+OK 1 ");
        checker(1, "+OK  1  ");
        checker(1, "+OK        1          ");
        checker(1, "+OK 1.2");
        checker(1, "+OK 1.2 ");
        checker(1, "+OK  1.2");
        checker(1, "+OK 1.2  ");
        checker(1, "+OK  1.2  ");
        checker(1, "+OK        1.2          ");
        checker(3, "+OK a b c");
        checker(3, "+OK a b c ");
        checker(3, "+OK a! b c:");
    }
}

//====================================================================
pub trait MyPop3ParserOfStatusLineAsForListAll {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_list_all(&self) -> Result<(Option<MyPop3NumberOfMessages>, Option<MyPop3Octets>)>;
    fn rebuild_as_for_list_all(&self, total_count: &MyPop3NumberOfMessages, total_nbytes: &MyPop3Octets) -> Self;
}

impl MyPop3ParserOfStatusLineAsForListAll for MyPop3StatusLine {
    fn parse_as_for_list_all(&self) -> Result<(Option<MyPop3NumberOfMessages>, Option<MyPop3Octets>)> {
        assert!(self.is_ok());
        let total_count = my_regex_extract_group_2(&REGEX_FOR_NUMBER_OF_MESSAGES, self.as_str())?;
        let total_nbytes = my_regex_extract_group_2(&REGEX_FOR_OCTETS, self.as_str())?;
        Ok((total_count, total_nbytes))
    }

    fn rebuild_as_for_list_all(&self, total_count: &MyPop3NumberOfMessages, total_nbytes: &MyPop3Octets) -> Self {
        assert!(self.is_ok());
        let ss = self.raw_line.as_str();
        let ss = my_regex_replace_group_2(&REGEX_FOR_NUMBER_OF_MESSAGES, &ss, |_| total_count.to_string());
        let ss = my_regex_replace_group_2(&REGEX_FOR_OCTETS, &ss, |_| total_nbytes.to_string());
        Self::from_str(&ss).unwrap()
    }
}

//====================
pub trait MyPop3ParserOfStatusLineAsForListSingle {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_list_single(&self) -> Result<MyPop3ScanListingItem>;
    fn rebuild_as_for_list_single(&self, message_number: &MyPop3MessageNumber, nbytes: &MyPop3Octets) -> Self;
}

impl MyPop3ParserOfStatusLineAsForListSingle for MyPop3StatusLine {
    fn parse_as_for_list_single(&self) -> Result<MyPop3ScanListingItem> {
        assert!(self.is_ok());
        self.as_rest_of_line().parse()
    }
    fn rebuild_as_for_list_single(&self, message_number: &MyPop3MessageNumber, nbytes: &MyPop3Octets) -> Self {
        // panic if does not seem to be a response for LIST_SINGLE command
        assert!(self.is_ok());
        let old_item = self.parse_as_for_list_single().unwrap();
        assert_eq!(message_number, old_item.as_message_number(), "{:?}", (&old_item, &message_number, &nbytes, &self));
        let new_item = old_item.rebuild_with_nbytes(&message_number, &nbytes);
        let it = self.fields.iter().take(2).map(|x| x.as_str().to_string());
        let it = it.chain([new_item.to_string()].into_iter());
        let ss = it.collect::<Vec<_>>().join("");
        Self::from_str(&ss).unwrap()
    }
}

//====================
pub trait MyPop3ParserOfStatusLineAsForRetr {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_retr(&self) -> Result<Option<MyPop3Octets>>;
    fn rebuild_as_for_retr(&self, nbytes: &MyPop3Octets) -> Self;
}

impl MyPop3ParserOfStatusLineAsForRetr for MyPop3StatusLine {
    fn parse_as_for_retr(&self) -> Result<Option<MyPop3Octets>> {
        assert!(self.is_ok());
        let nbytes = my_regex_extract_group_2(&REGEX_FOR_OCTETS, self.as_str())?;
        Ok(nbytes)
    }

    fn rebuild_as_for_retr(&self, nbytes: &MyPop3Octets) -> Self {
        // panic if does not seem to be a response for RETR command
        #![allow(unused)]
        unimplemented!()
    }
}

//====================
pub trait MyPop3ParserOfStatusLineAsForStat {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_stat(&self) -> Result<(MyPop3NumberOfMessages, MyPop3Octets)>;
    fn rebuild_as_for_stat(&self, total_count: &MyPop3NumberOfMessages, total_nbytes: &MyPop3Octets) -> Self;
}

impl MyPop3ParserOfStatusLineAsForStat for MyPop3StatusLine {
    fn parse_as_for_stat(&self) -> Result<(MyPop3NumberOfMessages, MyPop3Octets)> {
        assert!(self.is_ok());
        let args = self.to_args();
        if args.len() < 2 {
            // NOTE: RFC1939 says "This memo makes no requirement on what follows the maildrop size"
            return Err(anyhow!("the status line of the response for STAT should have at least two arguments: {:?}", (&args, &self)));
        }
        let num_of_messages = args[0].as_str().try_into()?;
        let nbytes = args[1].as_str().try_into()?;
        Ok((num_of_messages, nbytes))
    }

    fn rebuild_as_for_stat(&self, total_count: &MyPop3NumberOfMessages, total_nbytes: &MyPop3Octets) -> Self {
        // panic if does not seem to be a response for STAT command
        assert!(self.is_ok());
        let _ = self.parse_as_for_stat().unwrap(); // check if assertion failure
        let new_args = [total_count.to_string(), total_nbytes.to_string()];
        self.rebuild_with_args(&new_args)
    }
}

//====================
#[allow(unused)]
pub trait MyPop3ParserOfStatusLineAsForTop: MyPop3ParserOfStatusLineAsForRetr {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_top(&self) -> Result<Option<MyPop3Octets>>;
    fn rebuild_as_for_top(&self, nbytes: &MyPop3Octets) -> Self;
}

impl MyPop3ParserOfStatusLineAsForTop for MyPop3StatusLine {
    fn parse_as_for_top(&self) -> Result<Option<MyPop3Octets>> {
        #![allow(unused)]
        self.parse_as_for_retr()
    }

    fn rebuild_as_for_top(&self, nbytes: &MyPop3Octets) -> Self {
        // panic if does not seem to be a response for TOP command
        #![allow(unused)]
        unimplemented!()
    }
}

//====================
#[allow(unused)]
pub trait MyPop3ParserOfStatusLineAsForUidlAll {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_uidl_all(&self) -> Result<()>;
    fn rebuild_as_for_uidl_all(&self) -> Self;
}

impl MyPop3ParserOfStatusLineAsForUidlAll for MyPop3StatusLine {
    fn parse_as_for_uidl_all(&self) -> Result<()> {
        // RFC1939 does not say about the string which follows `+OK` indicator
        assert!(self.is_ok());
        Ok(())
    }

    fn rebuild_as_for_uidl_all(&self) -> Self {
        assert!(self.is_ok());
        self.clone()
    }
}

//====================
#[allow(unused)]
pub trait MyPop3ParserOfStatusLineAsForUidlSingle {
    // NOTE: avoid generic because it causes to need "type annotation" in caller side.
    fn parse_as_for_uidl_single(&self) -> Result<MyPop3UniqueIdListingItem>;
    fn rebuild_as_for_uidl_single(&self, message_number: &MyPop3MessageNumber, unique_id: &MyPop3UniqueID) -> Self;
}

impl MyPop3ParserOfStatusLineAsForUidlSingle for MyPop3StatusLine {
    fn parse_as_for_uidl_single(&self) -> Result<MyPop3UniqueIdListingItem> {
        assert!(self.is_ok());
        self.as_rest_of_line().parse()
    }

    fn rebuild_as_for_uidl_single(&self, message_number: &MyPop3MessageNumber, unique_id: &MyPop3UniqueID) -> Self {
        #![allow(unused)]
        unimplemented!()
    }
}

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[allow(non_camel_case_types)]
#[allow(unused)]
pub enum MyPop3StateName {
    AUTHORIZATION_0,
    AUTHORIZATION_1,
    TRANSACTION,
    // UPDATE, // `UPDATE` state is described in RFC1939, but not used in fubaco
    TERMINATED, // fubaco original (not defined in RFC1939)
}

//====================================================================
#[derive(Debug)]
#[allow(unused)]
pub struct MyPop3State {
    name: MyPop3StateName,
}

impl MyPop3State {
    #![allow(unused)]

    pub fn new() -> Self {
        Self {
            name: MyPop3StateName::AUTHORIZATION_0,
        }
    }

    pub fn name(&self) -> MyPop3StateName {
        self.name
    }

    pub fn is_acceptable_command(&self, command_name: MyPop3CommandName) -> bool {
        let expected_states: &[MyPop3StateName] = match command_name {
            MyPop3CommandName::APOP => &[MyPop3StateName::AUTHORIZATION_0],
            MyPop3CommandName::DELE => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::LIST => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::NOOP => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::PASS => &[MyPop3StateName::AUTHORIZATION_1],
            MyPop3CommandName::QUIT => &[MyPop3StateName::AUTHORIZATION_0, MyPop3StateName::AUTHORIZATION_1, MyPop3StateName::TRANSACTION],
            MyPop3CommandName::RETR => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::RSET => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::STAT => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::TOP  => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::UIDL => &[MyPop3StateName::TRANSACTION],
            MyPop3CommandName::USER => &[MyPop3StateName::AUTHORIZATION_0],
        };
        expected_states.contains(&self.name)
    }

    pub fn transition(&mut self, command_name: MyPop3CommandName, is_ok_response: bool) -> Result<()> {
        use MyPop3StateName::*; // import all state names

        let choice = |by_ok: MyPop3StateName, by_err: MyPop3StateName| {
            if is_ok_response {
                by_ok
            } else {
                by_err
            }
        };

        let stay = self.name;
        let next_state = match (self.name, command_name) {
            (AUTHORIZATION_0, MyPop3CommandName::USER) => choice(AUTHORIZATION_1, stay), // retry if failed
            (AUTHORIZATION_0, MyPop3CommandName::QUIT) => TERMINATED,
            (AUTHORIZATION_0, MyPop3CommandName::APOP) => choice(TRANSACTION, stay), // retry if failed

            (AUTHORIZATION_1, MyPop3CommandName::PASS) => choice(TRANSACTION, AUTHORIZATION_0), // retry if failed
            (AUTHORIZATION_1, MyPop3CommandName::QUIT) => TERMINATED,

            (TRANSACTION,     MyPop3CommandName::DELE) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::LIST) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::NOOP) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::RETR) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::RSET) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::STAT) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::TOP)  => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::UIDL) => choice(stay, TERMINATED),
            (TRANSACTION,     MyPop3CommandName::QUIT) => TERMINATED,

            _ => return Err(anyhow!("{} command is not allowed in {} state", command_name, self.name)),
        };

        self.name = next_state;
        Ok(())
    }
}

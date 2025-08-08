use chrono;

#[derive(Debug)]
pub struct MyTimestamp {
    value: chrono::DateTime<chrono::Local>,
}

impl MyTimestamp {
    #[allow(dead_code)]
    pub fn now() -> Self {
        MyTimestamp {
            value: chrono::Local::now(),
        }
    }

    pub fn to_int(&self) -> i64 { // elapsed seconds from UNIX EPOCH
        self.value.timestamp()
    }

    pub fn to_str(&self) -> String {
        self.value.format("%Y/%m/%d %H:%M:%S").to_string()
    }
}

impl From<i64> for MyTimestamp {
    fn from(value: i64) -> Self {
        Self {
            value: chrono::DateTime::from_timestamp(value, 0).unwrap().into(),
        }
    }
}

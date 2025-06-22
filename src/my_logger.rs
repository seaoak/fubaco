use std::fs::File;

use lazy_static::lazy_static;
use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{self, prelude::*};

#[allow(unused)]
pub mod prelude {

    // the order of log level: TRACE < DEBUG < INFO < WARN < ERROR < OFF
    pub use tracing::{debug, error, info, trace, warn};
}

lazy_static! {
    static ref FILEPATH_TO_LOG_FILE: String = "./fubaco.log".to_string();
}

pub fn init() {
    let timer = tracing_subscriber::fmt::time::LocalTime::new(format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"));

    let filter_for_stdout = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy(); // you can change log level by the environment variable `RUST_LOG`
    let stdout_logger = tracing_subscriber::fmt::layer()
        .without_time()
        .with_ansi(false)
        .with_file(false)
        .with_level(false)
        .with_line_number(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact()
        .with_filter(filter_for_stdout);

    let filter_for_logfile = LevelFilter::TRACE;
    let logfile_logger = (|| -> std::io::Result<_> {
        let file = File::options().append(true).create(true).open(FILEPATH_TO_LOG_FILE.as_str())?;
        let logger = tracing_subscriber::fmt::layer()
            .with_timer(timer) // with local timestamp
            .with_ansi(false)
            .with_file(false)
            .with_level(true)
            .with_line_number(false)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_writer(file)
            .compact()
            .with_filter(filter_for_logfile);
        Ok(logger)
    })().ok();

    let subscriber = tracing_subscriber::Registry::default()
        .with(stdout_logger)
        .with(logfile_logger);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

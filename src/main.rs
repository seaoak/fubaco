use std::env;
use std::fs::File;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use lazy_static::lazy_static;
use regex::Regex;
use rustls;
use tokio;
use webpki_roots;

mod my_crypto;
mod my_disconnect;
mod my_dkim_verifier;
mod my_dns_resolver;
mod my_dmarc_verifier;
mod my_fqdn;
mod my_fubaco_header;
mod my_message_parser;
mod my_logger;
mod my_plugin_yondakiji;
mod my_plugin_yondatweet;
mod my_pop3_command;
mod my_pop3_downstream;
mod my_pop3_bridge;
mod my_pop3_upstream;
mod my_spam_checker;
mod my_spf_verifier;
mod my_str;
mod my_text_line_stream;
mod my_timestamp;

use my_crypto::*;
use my_dns_resolver::MyDNSResolver;
use my_logger::prelude::*;

//====================================================================
fn main() {
    println!("Hello, world!");

    my_logger::init();
    trace!("This is TRACE message for MyLogger");
    debug!("This is DEBUG message for MyLogger");
    info!("This is INFO message for MyLogger");
    warn!("This is WARN message for MyLogger");
    error!("This is ERROR message for MyLogger");

    let fubaco_mode = env::var("FUBACO_MODE").unwrap_or_default();

    let status = match fubaco_mode.as_str() {
        "test_my_crypto" => test_my_crypto(),
        "test_my_dns_resolver" => test_my_dns_resolver(),
        "test_rustls_my_client" => test_rustls_my_client(),
        "test_rustls_simple_client" => test_rustls_simple_client(),
        "test_spam_checker_with_local_files" => test_spam_checker_with_local_files(),
        "test_pop3_bridge" => test_pop3_bridge(),
        "" => test_spam_checker_with_local_files(),
        _ => {
            println!("ERROR: unknown string in the environment variable \"FUBACO_MODE\": {}", fubaco_mode);
            std::process::exit(1);
        },
    };

    match status {
        Ok(()) => (),
        Err(e) => panic!("{:?}", e),
    }

    std::process::exit(0);
}

lazy_static! {
    static ref MY_DNS_RESOLVER: Arc<MyDNSResolver> = Arc::new(MyDNSResolver::new());
}

fn test_my_crypto() -> Result<()> {
    {
        let input_text = "";
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha1, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha1: {}", input_text, base64_string);
        assert_eq!(base64_string, "2jmj7l5rSw0yVb/vlWAYkK/YBwk="); // see "section 3.4.4" in RFC6376
    }
    {
        let input_text = "\r\n"; // CRLF
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha1, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha1: {}", input_text, base64_string);
        assert_eq!(base64_string, "uoq1oCgLlTqpdDX/iUbLy7J1Wic="); // see "section 3.4.3" in RFC6376
    }
    {
        let input_text = "";
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha256, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha256: {}", input_text, base64_string);
        assert_eq!(base64_string, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="); // see "section 3.4.4" in RFC6376
    }
    {
        let input_text = "\r\n"; // CRLF
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha256, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha256: {}", input_text, base64_string);
        assert_eq!(base64_string, "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="); // see "section 3.4.3" in RFC6376
    }
    Ok(())
}

fn test_my_dns_resolver() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            println!("Hello world in tokio");
            let queries = [
                ("seaoak.jp", "A"),
                ("seaoak.jp", "AAAA"),
                ("seaoak.jp", "TXT"),
                ("_dmarc.seaoak.jp", "TXT"),
            ];
            let mut infos = Vec::new();
            for (fqdn, query_type) in queries {
                let resolver = MY_DNS_RESOLVER.clone();
                let handle = tokio::spawn(async move {
                    resolver.lookup(fqdn.to_string(), query_type.to_string()).await
                });
                infos.push((fqdn, query_type, handle));
            }
            for info in infos {
                let (fqdn, query_type, handle) = info;
                let results = handle.await??;
                for result in results {
                    println!("Result: {} {} \"{}\"", fqdn, query_type, result);
                }
            }
            Ok::<(), anyhow::Error>(())
        })?;
    Ok(())
}

fn test_rustls_my_client() -> Result<()> {
    let upstream_hostname = "seaoak.jp".to_string();
    let upstream_port = 443;

    let tls_root_store =
        rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    let tls_config =
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(tls_root_store)
                .with_no_client_auth(),
        );
    let upstream_host = upstream_hostname.clone().try_into().unwrap();
    let mut upstream_tls_connection = rustls::ClientConnection::new(tls_config, upstream_host)?;
    let mut upstream_tcp_socket = TcpStream::connect(format!("{}:{}", upstream_hostname, upstream_port))?;
    let mut upstream_tls_stream = rustls::Stream::new(&mut upstream_tls_connection, &mut upstream_tcp_socket);

    println!("issue HTTP request");
    upstream_tls_stream.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: seaoak.jp\r\n",
            // "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n",
        ).as_bytes(),
    )?;
    let ciphersuite = upstream_tls_stream.conn.negotiated_cipher_suite().unwrap();
    eprintln!("Current ciphersuite: {:?}", ciphersuite.suite());
    let mut plaintext = Vec::new();
    let mut local_buf = [0u8; 1024];
    loop {
        let nbytes = match upstream_tls_stream.read(&mut local_buf) {
            Ok(0) => return Err(anyhow!("steam is closed unexpectedly")),
            Ok(len) => len,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                eprintln!("retry read()");
                // upstream_tls_connection.process_new_packets()?;
                continue;
            },
            Err(e) => return Err(anyhow!(e)),
        };
        plaintext.extend(&local_buf[0..nbytes]);
        if my_text_line_stream::ends_with_u8(&plaintext, b"</html>\n") { // allow empty line
            eprintln!("detect last LF");
            break;
        }
    }
    eprintln!("------------------------------");
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn test_rustls_simple_client() -> Result<()> {
    let upstream_hostname = "seaoak.jp".to_string();
    let upstream_port = 443;

    let tls_root_store =
        rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    let tls_config =
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(tls_root_store)
                .with_no_client_auth()
        );
    let upstream_host = upstream_hostname.clone().try_into().unwrap();
    let mut upstream_tls_connection = rustls::ClientConnection::new(tls_config, upstream_host)?;
    let mut upstream_tcp_socket = TcpStream::connect(format!("{}:{}", upstream_hostname, upstream_port))?;
    let mut upstream_tls_stream = rustls::Stream::new(&mut upstream_tls_connection, &mut upstream_tcp_socket);

    println!("issue HTTP request");
    upstream_tls_stream.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: seaoak.jp\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n",
        ).as_bytes(),
    )?;
    let ciphersuite = upstream_tls_stream.conn.negotiated_cipher_suite().unwrap();
    eprintln!("Current ciphersuite: {:?}", ciphersuite.suite());
    let mut plaintext = Vec::new();
    upstream_tls_stream.read_to_end(&mut plaintext)?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn test_spam_checker_with_local_files() -> Result<()> {
    let start_time = time::Instant::now();
    let path_to_dir = std::path::Path::new("./mail-sample");
    let mut list_of_result: Vec<std::result::Result<String, String>> = Vec::new();
    for entry in path_to_dir.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let filename = entry.file_name().to_string_lossy().to_string();
        if !filename.starts_with("mail-sample.") || !filename.ends_with(".eml") {
            continue;
        }
        info!("------------------------------------------------------------------------------");
        info!("FILE: {}", filename);
        let f = File::open(entry.path())?;
        let mut reader = BufReader::new(f);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let fubaco_headers = my_fubaco_header::make_fubaco_headers(&buf, &MY_DNS_RESOLVER)?;
        info!("{}", fubaco_headers);

        lazy_static! {
            static ref REGEX_FILENAME_AS_SUCCESSFUL: Regex = Regex::new(r"[-._](ok|pass|valid)[-._]").unwrap();
            static ref REGEX_FILENAME_AS_AUTHENTICATION: Regex = Regex::new(r"(?i)[-._](SPF|DKIM|DMARC)[-._]").unwrap(); // case-insensitive
        }
        let is_expected_to_pass = REGEX_FILENAME_AS_SUCCESSFUL.is_match(&filename);
        let is_test_for_auth = REGEX_FILENAME_AS_AUTHENTICATION.is_match(&filename);
        let is_passed = if is_test_for_auth {
            fubaco_headers.contains("dmarc=pass")
        } else {
            fubaco_headers.contains("X-Fubaco-Spam-Judgement: none")
        };
        let mode = if is_test_for_auth { "auth" } else { "judge" };
        let msg = format!("result={} / expected={} / mode={} / filename={:?}", is_passed, is_expected_to_pass, &mode, &filename);
        if is_passed == is_expected_to_pass {
            list_of_result.push(Ok(msg));
        } else {
            error!("TEST FAILED: {}", &msg);
            list_of_result.push(Err(msg));
            // unreachable!();
        }
    }

    info!("------------------------------------------------------------------------------");
    MY_DNS_RESOLVER.save_cache()?;
    info!("Elapsed time: {:.3} sec", start_time.elapsed().as_secs_f32());

    let total_count = list_of_result.len();
    let count_of_ng = list_of_result.iter().filter(|x| x.is_err()).count();
    let count_of_ok = total_count - count_of_ng;
    info!("Test summary: pass={} fail={} total={}", count_of_ok, count_of_ng, total_count);
    if count_of_ng > 0 {
        println!("test failed");
        std::process::exit(1);
    }
    Ok(())
}

fn test_pop3_bridge() -> Result<()> {
    my_pop3_bridge::run_pop3_bridge(&MY_DNS_RESOLVER)
}

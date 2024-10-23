use std::env;
use std::fs::File;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use lazy_static::lazy_static;
use mail_parser::MessageParser;
use my_dmarc_verifier::{DMARCResult, DMARCStatus};
use rustls;
use tokio;
use webpki_roots;

mod my_crypto;
mod my_disconnect;
mod my_dkim_verifier;
mod my_dns_resolver;
mod my_dmarc_verifier;
mod my_message_parser;
mod my_pop3_bridge;
mod my_spam_checker;
mod my_spf_verifier;
mod my_text_line_stream;
mod pop3_upstream;

use my_crypto::*;
use my_dkim_verifier::{DKIMResult, DKIMStatus};
use my_dns_resolver::MyDNSResolver;
use my_message_parser::MyMessageParser;
use my_spf_verifier::{SPFResult, SPFStatus};
use my_text_line_stream::MyTextLineStream;
use pop3_upstream::*;

//====================================================================
fn main() {
    println!("Hello, world!");

    assert_eq!(intersect_vec(&vec![1, 2, 3, 4, 5], &vec![2, 4, 6, 8]), vec![&2, &4]);

    let fubaco_mode = env::var("FUBACO_MODE").unwrap_or_default();

    let status = match fubaco_mode.as_str() {
        "test_my_crypto" => test_my_crypto(),
        "test_my_dns_resolver" => test_my_dns_resolver(),
        "test_rustls_my_client" => test_rustls_my_client(),
        "test_rustls_simple_client" => test_rustls_simple_client(),
        "test_spam_checker_with_local_files" => test_spam_checker_with_local_files(),
        "test_pop3_bridge" => test_pop3_bridge(),
        "test_pop3_upstream" => test_pop3_upstream(),
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

fn intersect_vec<'a, 'b, S>(a: &'a [S], b: &'b [S]) -> Vec<&'a S>
    where S: PartialEq + Sized
{
    a.iter().filter(|aa| b.contains(aa)).collect()
}

fn make_fubaco_padding_header(nbytes: usize) -> String { // generate just-nbyte-sized "X-Fubaco-Padding" header
    let line_length_limit = 80;
    let headding = "X-Fubaco-Padding: ".to_string();
    assert!(nbytes >= headding.len() + "x\r\n".len()); // at least one "x" is necessary
    let mut buf = format!("{}{}\r\n", headding, "x".repeat(nbytes - headding.len() - "\r\n".len())); // if line length is no limit

    // split buf into multi-line
    let mut pos = line_length_limit - "\r\n".len();
    while pos <= buf.len() - "\r\n\tx\r\n".len() {
        buf.replace_range(pos..(pos + "\r\n\t".len()), "\r\n\t");
        pos += line_length_limit;
    }
    if pos < buf.len() { // odd position
        pos = buf.len() - "\r\n\tx\r\n".len(); // roll back
        buf.replace_range(pos..(pos + "\r\n\t".len()), "\r\n\t");
    }
    assert!(buf.ends_with("x\r\n")); // at least one "x" is contained in last line
    buf
}

lazy_static! {
    static ref FUBACO_HEADER_TOTAL_SIZE: usize = 512; // (78+2)*6+(30+2)
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
        if MyTextLineStream::<TcpStream>::ends_with_u8(&plaintext, b"</html>\n") { // allow empty line
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

fn make_fubaco_headers(message_u8: &[u8]) -> Result<String> {
    let message;
    if let Some(v) = MessageParser::default().parse(message_u8) {
        message = v;
    } else {
        return Err(anyhow!("can not parse the message"));
    }

    let mut spam_judgement: Vec<String> = [
        my_spam_checker::spam_checker_suspicious_envelop_from,
        my_spam_checker::spam_checker_blacklist_tld,
        my_spam_checker::spam_checker_suspicious_from,
        my_spam_checker::spam_checker_suspicious_hyperlink,
        my_spam_checker::spam_checker_hidden_text_in_html,
        my_spam_checker::spam_checker_fully_html_encoded_text,
        my_spam_checker::spam_checker_suspicious_delivery_report,
    ].iter().filter_map(|f| f(&message)).collect();
    if spam_judgement.len() == 0 {
        spam_judgement.push("none".to_string());
    }

    let table_of_authentication_results_header = message.get_authentication_results();

    let mut spf_result = my_spf_verifier::spf_verify(&message, &MY_DNS_RESOLVER);
    if let Some(table) = &table_of_authentication_results_header {
        if let Some(mx_spf_status) = table.get("spf") {
            let mx_spf_status = mx_spf_status.parse::<SPFStatus>().unwrap(); // TODO: unknonw string may have to be an error, not panic
            if &mx_spf_status != spf_result.as_status() {
                println!("WARNING: my SPF checker says different result to \"Authentication-Results\" header: my={} vs header={}", spf_result.as_status(), mx_spf_status);
            }
            let my_spf_domain_list = spf_result.as_domains().clone();
            let mx_spf_domain_list = table.get("spf-target-domains").map(|s| s.split(',').map(str::to_string).collect::<Vec<String>>()).unwrap_or_default();
            if my_spf_domain_list.len() > 0 && mx_spf_domain_list.len() > 0 && intersect_vec(&my_spf_domain_list, &mx_spf_domain_list).len() == 0 {
                println!("WARNING: my SPF checker says different target domain to \"Authentication-Results\" header: my={:?} vs header={:?}", my_spf_domain_list, mx_spf_domain_list);
            }
            if mx_spf_status != SPFStatus::NONE {
                spf_result = SPFResult::new(mx_spf_status, mx_spf_domain_list); // overwrite
            }
        }
    }
    let mut dkim_result = my_dkim_verifier::dkim_verify(&message, &MY_DNS_RESOLVER);
    if let Some(table) = &table_of_authentication_results_header {
        let mx_label = ["dkim", "dkim-adsp"].into_iter().filter(|s| table.contains_key(*s)).take(1).next();
        if let Some(mx_label) = mx_label {
            let mx_dkim_status = table.get(mx_label).unwrap();
            let mx_dkim_status = mx_dkim_status.parse::<DKIMStatus>().unwrap(); // TODO: unknown string may have to be an error, not panic
            if &mx_dkim_status != dkim_result.as_status() {
                println!("WARNING: my DKIM checker says different result to \"Authentication-Results\" header: my={} vs header={}", dkim_result.as_status(), mx_dkim_status);
            }
            let my_dkim_domain_list = dkim_result.as_domains().clone();
            let mx_dkim_domain_list = table.get(&format!("{}-target-domains", mx_label)).map(|s| s.split(',').map(str::to_string).collect::<Vec<String>>()).unwrap_or_default();
            if my_dkim_domain_list.len() > 0 && mx_dkim_domain_list.len() > 0 && intersect_vec(&my_dkim_domain_list, &mx_dkim_domain_list).len() == 0 {
                println!("WARNING: my DKIM checker says different target domain to \"Authentication-Results\" header: my={:?} vs header={:?}", my_dkim_domain_list, mx_dkim_domain_list);
            }
            if mx_dkim_status != DKIMStatus::NONE {
                dkim_result = DKIMResult::new(mx_dkim_status, mx_dkim_domain_list); // overwrite
            }
        }
    }
    let mut dmarc_result;
    {
        let spf_domain_list: Vec<String> = if spf_result.as_status() == &SPFStatus::PASS {
            spf_result.as_domains().clone()
        } else {
            Vec::new()
        };
        let dkim_domain_list: Vec<String> = if dkim_result.as_status() == &DKIMStatus::PASS {
            dkim_result.as_domains().clone()
        } else {
            Vec::new()
        };
        dmarc_result = my_dmarc_verifier::dmarc_verify(&message, &spf_domain_list, &dkim_domain_list, &MY_DNS_RESOLVER);
        if let Some(table) = &table_of_authentication_results_header {
            if let Some(mx_dmarc_status) = table.get("dmarc") {
                let mx_dmarc_status = mx_dmarc_status.parse::<DMARCStatus>().unwrap(); // TODO: unknown string may have to be an error, not panic
                if &mx_dmarc_status != dmarc_result.as_status() {
                    println!("WARNING: my DMARC checker says different result to \"Authentication-Results\" header: my={} vs header={}", dmarc_result.as_status(), mx_dmarc_status);
                }
                if mx_dmarc_status != DMARCStatus::NONE {
                    dmarc_result = DMARCResult::new(mx_dmarc_status, dmarc_result.as_policy().clone()); // overwrite
                }
            }
        }
    }

    let auth_results = vec![
        format!("spf={}", spf_result.as_status()),
        format!("dkim={}", dkim_result.as_status()),
        format!("dmarc={}", dmarc_result.as_status()),
    ];

    let mut fubaco_headers = Vec::new();
    fubaco_headers.push(format!("X-Fubaco-Spam-Judgement: {}\r\n", spam_judgement.join(" ")));
    fubaco_headers.push(format!("X-Fubaco-Authentication: {}\r\n", auth_results.join(" ")));
    let nbytes = fubaco_headers.iter().fold(0, |acc, s| acc + s.len());
    fubaco_headers.push(make_fubaco_padding_header(*FUBACO_HEADER_TOTAL_SIZE - nbytes));
    Ok(fubaco_headers.join(""))
}

fn test_spam_checker_with_local_files() -> Result<()> {
    let path_to_dir = std::path::Path::new("./mail-sample");
    for entry in path_to_dir.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let filename = entry.file_name().to_string_lossy().to_string();
        if !filename.starts_with("mail-sample.") || !filename.ends_with(".eml") {
            continue;
        }
        println!("------------------------------------------------------------------------------");
        println!("FILE: {}", filename);
        let f = File::open(entry.path())?;
        let mut reader = BufReader::new(f);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let fubaco_headers = make_fubaco_headers(&buf)?;
        print!("{}", fubaco_headers);
    }
    MY_DNS_RESOLVER.save_cache()?;
    Ok(())
}

fn test_pop3_bridge() -> Result<()> {
    my_pop3_bridge::run_pop3_bridge(&MY_DNS_RESOLVER)
}

fn test_pop3_upstream() -> Result<()> {
    let username = env::var("FUBACO_Nq2DYd4cFHGZ_U").unwrap();
    let password = env::var("FUBACO_AhCE3FNtfdJV_P").unwrap();
    let hostname = env::var("FUBACO_Km2TTTAEMErD_H").unwrap();
    let port = 995;

    println!("open upstream connection");
    let mut pop3_upstream = POP3Upstream::connect(&hostname, port)?;

    println!("wait for greeting response");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_GREETING, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue USER command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_USER, Some(username))?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue PASS command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_PASS, Some(password))?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue STAT command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_STAT, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue LIST command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_LIST_ALL, None)?;
    let (_, body) = match response {
        POP3Response::OkSingleLine(status) => panic!("BUG: unexpected single-line response: {}", status),
        POP3Response::OkMultiLine(status, body) => {
            println!("detect OK response: {}{}", status, String::from_utf8_lossy(&body));
            (status, body)
        },
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    };
    let mail_size_list: Vec<usize> = String::from_utf8_lossy(&body).lines().map(|line| line.split_whitespace().nth(1).unwrap()).map(|s| s.parse::<usize>().unwrap()).collect();
    println!("DEBUG: mail_size_list = {:?}\n", mail_size_list);

    println!("issue UIDL command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_UIDL_ALL, None)?;
    let (_, body) = match response {
        POP3Response::OkSingleLine(status) => panic!("BUG: unexpected single-line response: {}", status),
        POP3Response::OkMultiLine(status, body) => {
            println!("detect OK response: {}{}", status, String::from_utf8_lossy(&body));
            (status, body)
        },
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    };
    let mail_uid_list: Vec<String> = String::from_utf8_lossy(&body).lines().map(|line| line.split_whitespace().nth(1).unwrap().to_string()).collect();
    println!("DEBUG: mail_uid_list = {:?}\n", mail_uid_list);

    assert_eq!(mail_size_list.len(), mail_uid_list.len());
    let mail_list: Vec<(usize, String)> = mail_size_list.into_iter().zip(mail_uid_list.into_iter()).collect();
    println!("DEBUG: mail_list = {:?}\n", mail_list);

    println!("issue QUIT command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_QUIT, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("closing connection...");
    pop3_upstream.disconnect()?;
    println!("connection is successfully closed");

    Ok(())
}

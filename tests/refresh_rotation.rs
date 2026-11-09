use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use rbw::{config::Config, db::Db, error::Error};

const EMAIL: &str = "rotation-fixture@example.invalid";
const SECRET: &str = "fake-server-body-secret-never-display";
const FOLDERS: &str =
    r#"{"Data":[{"Id":"folder-id","Name":"encrypted-name"}]}"#;
const SYNC: &str = r#"{"Ciphers":[],"Folders":[],"Profile":{"Key":"protected-key","PrivateKey":"private-key","Organizations":[]}}"#;
const LIMIT: Duration = Duration::from_secs(20);

// Only child test processes receive these environment changes. The test runner
// never loads configuration or a database from its own environment.
fn child(root: &Path, scenario: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "fixture", "--nocapture"])
        .env_clear()
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("TMPDIR", root.join("tmp"))
        .env("ROTATION_ROOT", root)
        .env("ROTATION_SCENARIO", scenario)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + LIMIT;
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stdout.contains(SECRET) && !stderr.contains(SECRET));
            assert!(output.status.success(), "{stdout}\n{stderr}");
            return output;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("fixture timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn isolated(scenario: &str) {
    let scratch = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".local/state/agents/tmp");
    std::fs::create_dir_all(&scratch).unwrap();
    let root = tempfile::Builder::new()
        .prefix("rbw-refresh-rotation-")
        .tempdir_in(scratch)
        .unwrap();
    for dir in ["home", "config", "cache", "data", "runtime", "tmp"] {
        std::fs::create_dir(root.path().join(dir)).unwrap();
    }
    finish(child(root.path(), scenario));
}

#[test]
fn rotated_and_optional_refresh_tokens_survive_reload() {
    for mode in ["blocking", "async"] {
        for replacement in ["rotated", "absent", "null"] {
            isolated(&format!("{mode}:success:{replacement}"));
        }
    }
}

#[test]
fn refresh_is_durable_before_a_failing_business_retry() {
    for mode in ["blocking", "async"] {
        for failure in ["500", "malformed"] {
            isolated(&format!("{mode}:retry:{failure}"));
        }
    }
}

#[test]
fn rejected_and_invalid_refreshes_do_not_change_the_database_or_leak_bodies()
{
    for mode in ["blocking", "async"] {
        for failure in [
            "rejected",
            "json",
            "missing-access",
            "null-access",
            "empty-access",
            "wrong-access",
            "empty-refresh",
            "wrong-refresh",
        ] {
            isolated(&format!("{mode}:invalid:{failure}"));
        }
    }
}

#[test]
fn concurrent_processes_reload_tokens_inside_the_database_lock() {
    isolated("concurrent");
}

struct Step {
    method: &'static str,
    path: &'static str,
    token: &'static str,
    status: u16,
    body: String,
    saved: Option<(&'static str, &'static str)>,
    wait_for_second: bool,
}

fn business(
    mode: &str,
    token: &'static str,
    status: u16,
    body: &str,
) -> Step {
    Step {
        method: "GET",
        path: if mode == "async" {
            "/api/sync"
        } else {
            "/api/folders"
        },
        token,
        status,
        body: body.into(),
        saved: None,
        wait_for_second: false,
    }
}

fn refresh(token: &'static str, status: u16, body: String) -> Step {
    Step {
        method: "POST",
        path: "/identity/connect/token",
        token,
        status,
        body,
        saved: None,
        wait_for_second: false,
    }
}

fn read_request(
    stream: &mut TcpStream,
) -> (String, Vec<(String, String)>, String) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buf = [0; 1024];
        let count = stream.read(&mut buf).unwrap();
        assert!(count > 0, "incomplete request headers");
        bytes.extend_from_slice(&buf[..count]);
        assert!(bytes.len() < 65_536);
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let mut lines = header.lines();
    let request = lines.next().unwrap().to_owned();
    let headers: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| {
            (key.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    let length = headers
        .iter()
        .find(|(key, _)| key == "content-length")
        .map_or(0, |(_, value)| value.parse::<usize>().unwrap());
    assert!(length < 65_536);
    while bytes.len() < header_end + length {
        let mut buf = [0; 1024];
        let count = stream.read(&mut buf).unwrap();
        assert!(count > 0, "incomplete request body");
        bytes.extend_from_slice(&buf[..count]);
    }
    (
        request,
        headers,
        String::from_utf8(bytes[header_end..].to_vec()).unwrap(),
    )
}

fn serve(
    listener: TcpListener,
    steps: Vec<Step>,
    server: String,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        for step in steps {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        assert!(
                            Instant::now() < deadline,
                            "missing {} {}",
                            step.method,
                            step.path
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            let (request, headers, body) = read_request(&mut stream);
            assert_eq!(
                request,
                format!("{} {} HTTP/1.1", step.method, step.path)
            );
            if step.method == "GET" {
                assert!(headers.contains(&(
                    "authorization".into(),
                    format!("Bearer {}", step.token)
                )));
                assert!(body.is_empty());
            } else {
                let mut form: Vec<_> =
                    url::form_urlencoded::parse(body.as_bytes())
                        .into_owned()
                        .collect();
                form.sort();
                assert_eq!(
                    form,
                    vec![
                        ("client_id".into(), "cli".into()),
                        ("grant_type".into(), "refresh_token".into()),
                        ("refresh_token".into(), step.token.into()),
                    ]
                );
            }
            if let Some((access, refresh)) = step.saved {
                assert_tokens(&server, access, refresh);
            }
            if step.wait_for_second {
                let root =
                    PathBuf::from(std::env::var_os("ROTATION_ROOT").unwrap());
                std::fs::write(root.join("first-refresh"), []).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !root.join("second-ready").exists() {
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(5));
                }
                thread::sleep(Duration::from_millis(150));
            }
            write!(stream, "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", step.status, step.body.len(), step.body).unwrap();
        }
    })
}

fn assert_tokens(server: &str, access: &str, refresh: &str) {
    let db = Db::load(server, EMAIL).unwrap();
    assert_eq!(db.access_token.as_deref(), Some(access));
    assert_eq!(db.refresh_token.as_deref(), Some(refresh));
    assert_eq!(db.protected_key.as_deref(), Some("vault-marker"));
    assert_eq!(db.iterations, Some(123_456));
}

fn call(mode: &str) -> Result<(), Error> {
    if mode == "async" {
        let (key, private_key, organizations, entries) =
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(rbw::actions::sync())?;
        assert_eq!(key, "protected-key");
        assert_eq!(private_key, "private-key");
        assert!(organizations.is_empty() && entries.is_empty());
    } else {
        assert_eq!(
            rbw::actions::list_folders()?,
            vec![("folder-id".into(), "encrypted-name".into())]
        );
    }
    Ok(())
}

#[test]
#[ignore = "subprocess fixture; invoked only with isolated XDG directories"]
fn fixture() {
    let Ok(scenario) = std::env::var("ROTATION_SCENARIO") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("ROTATION_ROOT").unwrap());
    assert!(root.is_absolute());
    for (name, directory) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_RUNTIME_DIR", "runtime"),
        ("TMPDIR", "tmp"),
    ] {
        assert_eq!(
            PathBuf::from(std::env::var_os(name).unwrap()),
            root.join(directory)
        );
    }
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Trace)
        .try_init()
        .unwrap();
    if scenario.starts_with("worker-") {
        if scenario == "worker-second" {
            std::fs::write(root.join("second-ready"), []).unwrap();
        }
        call(if scenario == "worker-second" {
            "async"
        } else {
            "blocking"
        })
        .unwrap();
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let mut config = Config::new();
    config.email = Some(EMAIL.into());
    config.base_url = Some(server.clone());
    config.save().unwrap();
    let mut db = Db::new();
    db.access_token = Some("old-access".into());
    db.refresh_token = Some("old-refresh".into());
    db.protected_key = Some("vault-marker".into());
    db.iterations = Some(123_456);
    db.save(&server, EMAIL).unwrap();
    let original = std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap();

    if scenario == "concurrent" {
        let mut exchange = refresh(
            "old-refresh",
            200,
            r#"{"access_token":"new-access","refresh_token":"new-refresh"}"#
                .into(),
        );
        exchange.wait_for_second = true;
        let mut retry = business("blocking", "new-access", 200, FOLDERS);
        retry.saved = Some(("new-access", "new-refresh"));
        let steps = vec![business("blocking", "old-access", 401, "{}"), exchange, retry,
            business("async", "new-access", 401, "{}"),
            refresh("new-refresh", 200, r#"{"access_token":"latest-access","refresh_token":"latest-refresh"}"#.into()),
            business("async", "latest-access", 200, SYNC)];
        let handle = serve(listener, steps, server.clone());
        let root = PathBuf::from(std::env::var_os("ROTATION_ROOT").unwrap());
        let first = child(&root, "worker-first");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !root.join("first-refresh").exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let second = child(&root, "worker-second");
        finish(first);
        finish(second);
        handle.join().unwrap();
        assert_tokens(&server, "latest-access", "latest-refresh");
        return;
    }

    let parts: Vec<_> = scenario.split(':').collect();
    let (mode, kind, detail) = (parts[0], parts[1], parts[2]);
    let success = if mode == "async" { SYNC } else { FOLDERS };
    let mut steps = vec![business(mode, "old-access", 401, "{}")];
    if kind == "invalid" {
        let body = match detail {
            "rejected" => format!(
                r#"{{"error":"invalid_grant","error_description":"{SECRET}"}}"#
            ),
            "json" => format!("not-json-{SECRET}"),
            "missing-access" => format!(r#"{{"refresh_token":"{SECRET}"}}"#),
            "null-access" => format!(
                r#"{{"access_token":null,"refresh_token":"{SECRET}"}}"#
            ),
            "empty-access" => {
                format!(r#"{{"access_token":"","refresh_token":"{SECRET}"}}"#)
            }
            "wrong-access" => {
                format!(r#"{{"access_token":{{"secret":"{SECRET}"}}}}"#)
            }
            "empty-refresh" => {
                format!(r#"{{"access_token":"{SECRET}","refresh_token":""}}"#)
            }
            "wrong-refresh" => {
                format!(r#"{{"access_token":"{SECRET}","refresh_token":42}}"#)
            }
            _ => unreachable!(),
        };
        steps.push(refresh(
            "old-refresh",
            if detail == "rejected" { 400 } else { 200 },
            body,
        ));
        let handle = serve(listener, steps, server.clone());
        let error = call(mode).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(SECRET));
        if detail == "rejected" {
            assert!(matches!(error, Error::RefreshTokenRejected));
            assert!(error.to_string().contains("re-authentication"));
        } else {
            assert!(matches!(error, Error::InvalidRefreshResponse));
        }
        handle.join().unwrap();
        assert_eq!(
            std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap(),
            original
        );
        return;
    }
    let replacement = match detail {
        "absent" => "",
        "null" => r#", "refresh_token": null"#,
        _ => r#", "refresh_token": "new-refresh""#,
    };
    let expected_refresh = if matches!(detail, "absent" | "null") {
        "old-refresh"
    } else {
        "new-refresh"
    };
    steps.push(refresh(
        "old-refresh",
        200,
        format!(r#"{{"access_token":"new-access"{replacement}}}"#),
    ));
    let mut retry = business(
        mode,
        "new-access",
        if detail == "500" { 500 } else { 200 },
        if detail == "malformed" {
            "not-json"
        } else {
            success
        },
    );
    retry.saved = Some(("new-access", expected_refresh));
    steps.push(retry);
    if kind == "success" {
        steps.extend([
            business(mode, "new-access", 401, "{}"),
            refresh(expected_refresh, 200, r#"{"access_token":"latest-access","refresh_token":"latest-refresh"}"#.into()),
            business(mode, "latest-access", 200, success),
        ]);
    }
    let handle = serve(listener, steps, server.clone());
    if kind == "retry" {
        assert!(call(mode).is_err());
    } else {
        call(mode).unwrap();
    }
    assert_tokens(&server, "new-access", expected_refresh);
    if kind == "success" {
        call(mode).unwrap();
        assert_tokens(&server, "latest-access", "latest-refresh");
    }
    handle.join().unwrap();
}

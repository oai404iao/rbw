use std::{
    fs::File,
    io::{BufRead as _, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::{
        fd::FromRawFd as _,
        unix::{
            fs::{OpenOptionsExt as _, PermissionsExt as _},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use pkcs8::EncodePrivateKey as _;
use rbw::{api::KdfType, cipherstring::CipherString, config::Config, db::Db};
use serde_json::json;

const EMAIL: &str = "reauth-fixture@example.invalid";
const PASSWORD: &str = "fictitious-master-password";
const SECRET: &str = "fixture-server-body-must-not-be-displayed";
const LIMIT: Duration = Duration::from_secs(45);

fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!(
                "child timed out: {:?}",
                child.wait_with_output().unwrap()
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
}

fn isolated(scenario: &str) {
    let scratch = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".local/state/agents/tmp");
    std::fs::create_dir_all(&scratch).unwrap();
    let root = tempfile::Builder::new()
        .prefix("rbw-reauth-")
        .tempdir_in(scratch)
        .unwrap()
        .keep();
    for name in ["home", "config", "cache", "data", "runtime", "tmp"] {
        std::fs::create_dir(root.join(name)).unwrap();
    }
    eprintln!("reauth fixture {scenario}: {}", root.display());
    let output = finish(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "fixture", "--nocapture"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_RUNTIME_DIR", root.join("runtime"))
            .env("TMPDIR", root.join("tmp"))
            .env("REAUTH_ROOT", &root)
            .env("REAUTH_SCENARIO", scenario)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    success(&output);
}

#[test]
fn successful_reauthentication_and_totp_commit_new_credentials_and_keys() {
    for scenario in ["success", "totp-success"] {
        isolated(scenario);
    }
}

#[test]
fn failed_reauthentication_preserves_disk_and_live_keys() {
    for scenario in [
        "reject",
        "cancel",
        "wrong-password",
        "totp-failure",
        "network",
        "sync-500",
        "sync-malformed",
        "decrypt-failure",
        "login-malformed",
        "login-injected-error",
        "stale-snapshot",
        "prelogin-malformed",
        "sync-typed-malformed",
        "cipher-prefix-secret",
    ] {
        isolated(scenario);
    }
}

#[test]
fn background_and_noninteractive_sync_never_prompt() {
    for scenario in [
        "background",
        "initial-500",
        "initial-malformed",
        "refresh-403",
        "refresh-malformed",
        "refresh-network",
    ] {
        isolated(scenario);
    }
}

#[test]
fn concurrent_reauthentication_is_busy_without_a_second_prompt() {
    isolated("concurrent");
}

#[test]
fn old_agent_protocol_is_not_quit_or_replaced() {
    isolated("old-protocol");
}

#[test]
fn disconnected_cli_cancels_prompt_and_releases_reauthentication_gate() {
    isolated("disconnect");
}

#[test]
fn recovered_keys_autolock_from_locked_and_expired_sessions() {
    isolated("locked-success");
    isolated("expired-success");
}

#[test]
fn normal_sync_cannot_overwrite_a_reauthenticated_candidate() {
    isolated("sync-race");
    isolated("disconnect-commit");
}

// This executable implements only Assuan's fixture dialogue. Values and event
// files belong exclusively to the isolated child process.
const PINENTRY: &str = r#"#!/bin/sh
if test -p "$REAUTH_ROOT/pinentry-lifetime"; then
 exec 3> "$REAUTH_ROOT/pinentry-lifetime"
 printf 'active\n' >&3
fi
printf 'OK fixture ready\n'
prompt=''
while IFS= read -r line; do
 case "$line" in
 SETPROMPT*) prompt="$line"; printf 'OK\n';;
 CONFIRM*)
   printf 'CONFIRM\n' >> "$REAUTH_ROOT/prompts"
   while test -f "$REAUTH_ROOT/block"; do sleep 0.02; done
   if test -f "$REAUTH_ROOT/reject"; then printf 'ERR 83886179 cancelled\n'; else printf 'OK\n'; fi;;
 GETPIN*)
   printf 'GETPIN\n' >> "$REAUTH_ROOT/prompts"
   if test -f "$REAUTH_ROOT/cancel"; then printf 'ERR 83886179 cancelled\n'
   else
     case "$prompt" in
       *Master*) if test -f "$REAUTH_ROOT/wrong"; then printf 'D wrong-fixture-password\nOK\n'; else printf 'D fictitious-master-password\nOK\n'; fi;;
       *) printf 'D 123456\nOK\n';;
     esac
   fi;;
 BYE*) printf 'OK\n'; exit 0;;
 *) printf 'OK\n';;
 esac
done
"#;

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// The PTY is only stdin; output remains captured for diagnostics. Holding the
// master alive makes is_terminal true without involving a real user terminal.
fn cli(args: &[&str], interactive: bool) -> (Child, Option<File>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rbw"));
    // The fixture owns the foreground agent. Even a regression in CLI startup
    // must not discover an installed agent or leave a daemon behind.
    command.env(
        "RBW_AGENT",
        PathBuf::from(std::env::var_os("REAUTH_ROOT").unwrap())
            .join("forbidden-agent-autostart"),
    );
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let master = if interactive {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty writes two valid descriptors on success; each is
        // transferred exactly once into File, and no borrowed pointers escape.
        unsafe {
            assert_eq!(
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null()
                ),
                0
            );
            command.stdin(File::from_raw_fd(slave));
            Some(File::from_raw_fd(master))
        }
    } else {
        command.stdin(Stdio::null());
        None
    };
    (command.spawn().unwrap(), master)
}

fn run(args: &[&str], interactive: bool) -> Output {
    let (child, _master) = cli(args, interactive);
    finish(child)
}

fn request(action: rbw::protocol::Action) -> rbw::protocol::Response {
    let mut sock = UnixStream::connect(rbw::dirs::socket_file()).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    serde_json::to_writer(
        &mut sock,
        &rbw::protocol::Request::new(
            rbw::protocol::Environment::default(),
            action,
        ),
    )
    .unwrap();
    sock.write_all(b"\n").unwrap();
    let mut line = String::new();
    std::io::BufReader::new(sock).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn decrypt(cipher: &str, expected: &str, org_id: Option<&str>) {
    match request(rbw::protocol::Action::Decrypt {
        cipherstring: cipher.into(),
        entry_key: None,
        org_id: org_id.map(Into::into),
    }) {
        rbw::protocol::Response::Decrypt { plaintext } => {
            assert_eq!(plaintext, expected);
        }
        other => panic!("decrypt: {other:?}"),
    }
}

fn password() -> rbw::locked::Password {
    let mut bytes = rbw::locked::Vec::new();
    bytes.extend(PASSWORD.bytes());
    rbw::locked::Password::new(bytes)
}

struct Vault {
    protected: String,
    private: String,
    org: String,
    cipher: String,
    org_cipher: String,
}

fn vault(marker: u8) -> Vault {
    let mut bytes = rbw::locked::Vec::new();
    bytes.extend(std::iter::repeat_n(marker, 64));
    let keys = rbw::locked::Keys::new(bytes);
    let identity = rbw::identity::Identity::new(
        EMAIL,
        &password(),
        KdfType::Pbkdf2,
        2,
        None,
        None,
    )
    .unwrap();
    let encrypt = |keys, bytes: &[u8]| {
        CipherString::encrypt_symmetric(keys, bytes)
            .unwrap()
            .to_string()
    };
    let private =
        rsa::RsaPrivateKey::new(&mut rand_8::thread_rng(), 1024).unwrap();
    let org_bytes = [marker + 1; 64];
    let org = CipherString::Asymmetric {
        ciphertext: rsa::RsaPublicKey::from(&private)
            .encrypt(
                &mut rand_8::thread_rng(),
                rsa::Oaep::new::<sha1::Sha1>(),
                &org_bytes,
            )
            .unwrap(),
    }
    .to_string();
    let mut locked_org = rbw::locked::Vec::new();
    locked_org.extend(org_bytes.into_iter());
    let org_keys = rbw::locked::Keys::new(locked_org);
    Vault {
        protected: encrypt(&identity.keys, &[marker; 64]),
        private: encrypt(&keys, private.to_pkcs8_der().unwrap().as_bytes()),
        org,
        cipher: encrypt(&keys, format!("fixture-{marker}").as_bytes()),
        org_cipher: encrypt(
            &org_keys,
            format!("org-fixture-{marker}").as_bytes(),
        ),
    }
}

struct Mock {
    scenario: String,
    sync: String,
    key: String,
    hash: String,
    refreshes: Vec<String>,
    passwords: usize,
    syncs: usize,
}

fn read_http(stream: &mut TcpStream) -> (String, String, String) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let request = line.trim().to_owned();
    let (mut len, mut bearer) = (0, String::new());
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                len = value.trim().parse().unwrap();
            }
            if name.eq_ignore_ascii_case("authorization") {
                bearer = value.trim().into();
            }
        }
    }
    assert!(len < 65_536);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    (request, bearer, String::from_utf8(body).unwrap())
}

fn serve(
    listener: TcpListener,
    state: Arc<Mutex<Mock>>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let mut requests = vec![];
        while !stop.load(Ordering::SeqCst) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("accept: {e}"),
            };
            let state = state.clone();
            requests.push(thread::spawn(move || {
            let (req, bearer, body) = read_http(&mut stream);
            let root = PathBuf::from(std::env::var_os("REAUTH_ROOT").unwrap());
            if req == "GET /api/sync HTTP/1.1" && bearer == "Bearer old-access"
                && root.join("normal-race").exists() {
                std::fs::write(root.join("normal-started"), "").unwrap();
                wait_for(|| root.join("release-normal").exists());
                let body = std::fs::read_to_string(root.join("old-sync.json")).unwrap();
                write!(stream, "HTTP/1.1 200 Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                return;
            }
            let mut mock = state.lock().unwrap();
            let (status, body) = if req == "GET /api/sync HTTP/1.1" {
                mock.syncs += 1;
                if bearer == "Bearer old-access"
                    || bearer == "Bearer candidate-access"
                        && mock.scenario == "rotate"
                {
                    match mock.scenario.as_str() {
                        "initial-500" => (500, "{}".into()),
                        "initial-malformed" => (200, "not-json".into()),
                        _ => (401, "{}".into()),
                    }
                } else {
                    assert!(
                        bearer == "Bearer candidate-access"
                            || bearer == "Bearer rotated-access"
                    );
                    match mock.scenario.as_str() {
                        "sync-500" => (500, "{}".into()),
                        "sync-malformed" => (200, "not-json".into()),
                        "sync-typed-malformed" => (200, json!({"Ciphers":[],"Folders":[],"Profile":{"Key":{"secret":SECRET},"PrivateKey":"unused","Organizations":[]}}).to_string()),
                        _ => (200, mock.sync.clone()),
                    }
                }
            } else if req == "POST /identity/accounts/prelogin HTTP/1.1" {
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap()
                        ["email"],
                    EMAIL
                );
                (200, if mock.scenario == "prelogin-malformed" {
                    json!({"Kdf":0,"KdfIterations":SECRET}).to_string()
                } else { json!({"Kdf":0,"KdfIterations":2}).to_string() })
            } else {
                assert_eq!(req, "POST /identity/connect/token HTTP/1.1");
                let form: std::collections::HashMap<String, String> =
                    url::form_urlencoded::parse(body.as_bytes())
                        .into_owned()
                        .collect();
                if form["grant_type"] == "refresh_token" {
                    let token = form["refresh_token"].clone();
                    mock.refreshes.push(token.clone());
                    if token == "old-refresh" {
                        match mock.scenario.as_str() {
                            "refresh-403" => (403, "{}".into()),
                            "refresh-malformed" => (200, json!({"access_token":SECRET,"refresh_token":42}).to_string()),
                            "refresh-network" => return,
                            _ => (400, json!({"error":"invalid_grant"}).to_string()),
                        }
                    } else {
                        assert_eq!(token, "candidate-refresh");
                        (200, json!({"access_token":"rotated-access","refresh_token":"rotated-refresh"}).to_string())
                    }
                } else {
                    assert_eq!(form["grant_type"], "password");
                    assert_eq!(form["username"], EMAIL);
                    mock.passwords += 1;
                    if mock.scenario == "network" {
                        return;
                    }
                    if mock.scenario == "wrong-password" {
                        assert_ne!(form["password"], mock.hash);
                        (400, json!({"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":"Incorrect fixture password"}}).to_string())
                    } else {
                        assert_eq!(form["password"], mock.hash);
                        if mock.scenario == "login-malformed" {
                            (
                                200,
                                json!({"access_token":SECRET,"Key":SECRET})
                                    .to_string(),
                            )
                        } else if mock.scenario == "login-injected-error" {
                            (400, json!({"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":SECRET}}).to_string())
                        } else if mock.scenario.starts_with("totp-")
                            && !form.contains_key("twoFactorToken")
                        {
                            (400, json!({"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":[0]}).to_string())
                        } else if mock.scenario == "totp-failure" {
                            assert_eq!(form["twoFactorToken"], "123456");
                            (400, json!({"error":"invalid_grant","error_description":"invalid_totp"}).to_string())
                        } else {
                            if mock.scenario == "totp-success" {
                                assert_eq!(form["twoFactorToken"], "123456");
                                assert_eq!(form["twoFactorProvider"], "0");
                            }
                            (200, json!({"access_token":"candidate-access","refresh_token":"candidate-refresh","Key":mock.key}).to_string())
                        }
                    }
                }
            };
            write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            if req == "GET /api/sync HTTP/1.1" && bearer == "Bearer candidate-access"
                && matches!(mock.scenario.as_str(), "sync-race" | "disconnect-commit") {
                std::fs::write(root.join("candidate-ready"), "").unwrap();
            }
            }));
        }
        for request in requests {
            request.join().unwrap();
        }
    })
}

fn counts(root: &Path) -> (usize, usize) {
    let log =
        std::fs::read_to_string(root.join("prompts")).unwrap_or_default();
    (
        log.lines().filter(|s| *s == "CONFIRM").count(),
        log.lines().filter(|s| *s == "GETPIN").count(),
    )
}

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "fixture condition timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

fn old_protocol(root: &Path) {
    let listener =
        std::os::unix::net::UnixListener::bind(rbw::dirs::socket_file())
            .unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let requests = Arc::new(Mutex::new(0));
    let received = requests.clone();
    // Only the wire version is emulated; no installed/real old agent is run.
    let handle = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut line = String::new();
                    std::io::BufReader::new(&mut sock)
                        .read_line(&mut line)
                        .unwrap();
                    let request: rbw::protocol::Request =
                        serde_json::from_str(&line).unwrap();
                    assert!(matches!(request.into_parts().0, rbw::protocol::Action::Version),
                        "old agent must receive only Version, never Quit or Sync");
                    *received.lock().unwrap() += 1;
                    serde_json::to_writer(
                        &mut sock,
                        &rbw::protocol::Response::Version {
                            version: rbw::protocol::VERSION - 1,
                        },
                    )
                    .unwrap();
                    sock.write_all(b"\n").unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    });
    for args in [&["sync"][..], &["sync", "--reauth"][..]] {
        let output = run(args, true);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("protocol version"),
            "{output:?}"
        );
    }
    assert_eq!(*requests.lock().unwrap(), 2);
    assert_eq!(counts(root), (0, 0));
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
}

#[test]
#[ignore = "runs only in a child with isolated HOME and XDG directories"]
fn fixture() {
    let Ok(scenario) = std::env::var("REAUTH_SCENARIO") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("REAUTH_ROOT").unwrap());
    for (name, dir) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_RUNTIME_DIR", "runtime"),
        ("TMPDIR", "tmp"),
    ] {
        assert_eq!(
            PathBuf::from(std::env::var_os(name).unwrap()),
            root.join(dir)
        );
    }
    rbw::dirs::make_all().unwrap();
    let pinentry = root.join("pinentry");
    std::fs::write(&pinentry, PINENTRY).unwrap();
    std::fs::set_permissions(
        &pinentry,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let mut config = Config::new();
    config.email = Some(EMAIL.into());
    config.base_url = Some(server.clone());
    config.notifications_url = Some("http://127.0.0.1:1".into());
    config.pinentry = pinentry.to_str().unwrap().into();
    config.sync_interval = u64::from(scenario == "background");
    if matches!(scenario.as_str(), "locked-success" | "expired-success") {
        config.lock_timeout = 1;
    }
    config.save().unwrap();
    if scenario == "old-protocol" {
        old_protocol(&root);
        return;
    }
    let old = vault(11);
    let new = vault(22);
    let mut db = Db::new();
    db.access_token = Some("old-access".into());
    db.refresh_token = Some("old-refresh".into());
    db.kdf = Some(KdfType::Pbkdf2);
    db.iterations = Some(2);
    db.protected_key = Some(old.protected.clone());
    db.protected_private_key = Some(old.private.clone());
    db.protected_org_keys
        .insert("fixture-org".into(), old.org.clone());
    db.entries.push(rbw::db::Entry {
        id: "old-entry".into(),
        name: old.cipher.clone(),
        org_id: None,
        folder: None,
        folder_id: None,
        data: rbw::db::EntryData::SecureNote,
        notes: Some(old.cipher.clone()),
        fields: vec![],
        history: vec![],
        key: None,
        master_password_reprompt: rbw::api::CipherRepromptType::None,
    });
    assert!(!db.needs_login());
    db.save(&server, EMAIL).unwrap();
    let mut original =
        std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap();
    let private = match scenario.as_str() {
        "decrypt-failure" => "invalid-cipher".into(),
        "cipher-prefix-secret" => format!("{SECRET}.payload"),
        _ => new.private.clone(),
    };
    let sync = json!({"Ciphers":[{"Id":"new-entry","Name":new.cipher,
        "Notes":new.cipher,"SecureNote":{},"Reprompt":0}],"Folders":[],"Profile":{
        "Key":new.protected,"PrivateKey":private,
        "Organizations":[{"Id":"fixture-org","Key":new.org}]}}).to_string();
    let identity = rbw::identity::Identity::new(
        EMAIL,
        &password(),
        KdfType::Pbkdf2,
        2,
        None,
        None,
    )
    .unwrap();
    let mock = Arc::new(Mutex::new(Mock {
        scenario: scenario.clone(),
        sync,
        key: new.protected.clone(),
        hash: rbw::base64::encode(identity.master_password_hash.hash()),
        refreshes: vec![],
        passwords: 0,
        syncs: 0,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let handle = serve(listener, mock.clone(), stop.clone());
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_rbw-agent"))
            .arg("--no-daemonize")
            .stdout(File::create(root.join("agent.stdout")).unwrap())
            .stderr(File::create(root.join("agent.stderr")).unwrap())
            .spawn()
            .unwrap(),
    );
    wait_for(|| rbw::dirs::socket_file().exists());
    if scenario != "locked-success" {
        success(&run(&["unlock"], false));
        decrypt(&old.cipher, "fixture-11", None);
        decrypt(&old.org_cipher, "org-fixture-11", Some("fixture-org"));
    }
    std::fs::write(root.join("prompts"), "").unwrap();
    for (case, file) in [
        ("reject", "reject"),
        ("cancel", "cancel"),
        ("wrong-password", "wrong"),
    ] {
        if scenario == case {
            std::fs::write(root.join(file), "").unwrap();
        }
    }
    if scenario == "disconnect" {
        use std::os::unix::ffi::OsStrExt as _;
        let fifo = root.join("pinentry-lifetime");
        let name =
            std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated fixture-local path remains valid for the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let mut lifetime = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(fifo)
            .unwrap();
        std::fs::write(root.join("block"), "").unwrap();
        let (mut first, _master) = cli(&["sync", "--reauth"], true);
        wait_for(|| counts(&root).0 == 1);
        let mut marker = [0; 32];
        assert!(lifetime.read(&mut marker).unwrap() > 0);
        first.kill().unwrap();
        first.wait().unwrap();
        wait_for(|| match lifetime.read(&mut marker) {
            Ok(0) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            other => panic!("pinentry lifetime: {other:?}"),
        });
        assert_eq!(
            std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap(),
            original
        );
        assert_eq!(mock.lock().unwrap().passwords, 0);
        std::fs::remove_file(root.join("block")).unwrap();
        std::fs::write(root.join("reject"), "").unwrap();
        let result = run(&["sync", "--reauth"], true);
        assert!(!result.status.success(), "{result:?}");
        assert_eq!(counts(&root), (2, 0));
    } else if matches!(
        scenario.as_str(),
        "locked-success" | "expired-success"
    ) {
        std::fs::write(root.join("block"), "").unwrap();
        let (first, _master) = cli(&["sync", "--reauth"], true);
        wait_for(|| counts(&root).0 == 1);
        wait_for(|| {
            matches!(
                request(rbw::protocol::Action::CheckLock),
                rbw::protocol::Response::Error { .. }
            )
        });
        std::fs::remove_file(root.join("block")).unwrap();
        success(&finish(first));
        assert!(matches!(
            request(rbw::protocol::Action::CheckLock),
            rbw::protocol::Response::Ack
        ));
        // No decrypt/CLI lookup here: those reset the timer and would hide a
        // missing timeout installation at the candidate commit boundary.
        wait_for(|| {
            matches!(
                request(rbw::protocol::Action::CheckLock),
                rbw::protocol::Response::Error { .. }
            )
        });
        assert_eq!(counts(&root), (1, 1));
        assert_eq!(
            Db::load(&server, EMAIL).unwrap().refresh_token.as_deref(),
            Some("candidate-refresh")
        );
    } else if matches!(scenario.as_str(), "sync-race" | "disconnect-commit") {
        std::fs::write(root.join("old-sync.json"), json!({"Ciphers":[{"Id":"old-entry","Name":old.cipher,
            "Notes":old.cipher,"SecureNote":{},"Reprompt":0}],"Folders":[],"Profile":{
            "Key":old.protected,"PrivateKey":old.private,"Organizations":[{"Id":"fixture-org","Key":old.org}]}}).to_string()).unwrap();
        std::fs::write(root.join("block"), "").unwrap();
        let (mut first, _master) = cli(&["sync", "--reauth"], true);
        wait_for(|| counts(&root).0 == 1);
        std::fs::write(root.join("normal-race"), "").unwrap();
        let (normal, _normal_master) = cli(&["sync"], false);
        wait_for(|| root.join("normal-started").exists());
        std::fs::remove_file(root.join("block")).unwrap();
        wait_for(|| root.join("candidate-ready").exists());
        // The candidate is ready but the older normal response still owns the
        // sync-update critical section. It must complete before commit.
        thread::sleep(Duration::from_millis(200));
        assert!(first.try_wait().unwrap().is_none());
        assert_eq!(
            std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap(),
            original
        );
        if scenario == "disconnect-commit" {
            first.kill().unwrap();
            first.wait().unwrap();
            // Let the disconnect reach the pending commit-lock select before
            // releasing the older sync; no database write has begun yet.
            thread::sleep(Duration::from_millis(100));
            std::fs::write(root.join("release-normal"), "").unwrap();
            success(&finish(normal));
            std::fs::remove_file(root.join("normal-race")).unwrap();
            std::fs::write(root.join("reject"), "").unwrap();
            let result = run(&["sync", "--reauth"], true);
            assert!(!result.status.success(), "{result:?}");
            assert_eq!(counts(&root), (2, 1));
        } else {
            std::fs::write(root.join("release-normal"), "").unwrap();
            success(&finish(normal));
            success(&finish(first));
            decrypt(&new.cipher, "fixture-22", None);
            decrypt(&new.org_cipher, "org-fixture-22", Some("fixture-org"));
            let saved = Db::load(&server, EMAIL).unwrap();
            assert_eq!(
                saved.refresh_token.as_deref(),
                Some("candidate-refresh")
            );
            assert_eq!(
                saved.protected_key.as_deref(),
                Some(new.protected.as_str())
            );
            assert_eq!(saved.entries[0].id, "new-entry");
            assert_eq!(counts(&root), (1, 1));
        }
    } else if scenario == "background" {
        assert!(!run(&["sync"], true).status.success());
        assert!(!run(&["sync", "--reauth"], false).status.success());
        assert!(matches!(
            request(rbw::protocol::Action::Sync),
            rbw::protocol::Response::Error { .. }
        ));
        let syncs = mock.lock().unwrap().syncs;
        wait_for(|| mock.lock().unwrap().syncs > syncs);
        assert_eq!(counts(&root), (0, 0));
    } else if scenario == "stale-snapshot" {
        std::fs::write(root.join("block"), "").unwrap();
        let (first, _master) = cli(&["sync", "--reauth"], true);
        wait_for(|| counts(&root).0 == 1);
        let mut newer = Db::load(&server, EMAIL).unwrap();
        newer.refresh_token = Some("external-newer-refresh".into());
        newer.save(&server, EMAIL).unwrap();
        original = std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap();
        std::fs::remove_file(root.join("block")).unwrap();
        let output = finish(first);
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(counts(&root), (1, 1));
    } else if scenario == "concurrent" {
        std::fs::write(root.join("block"), "").unwrap();
        let (first, _master) = cli(&["sync", "--reauth"], true);
        wait_for(|| counts(&root).0 == 1);
        let second = run(&["sync", "--reauth"], true);
        assert!(!second.status.success(), "{second:?}");
        assert!(
            String::from_utf8_lossy(&second.stderr)
                .to_lowercase()
                .contains("progress")
                || String::from_utf8_lossy(&second.stderr)
                    .to_lowercase()
                    .contains("busy"),
            "{second:?}"
        );
        assert_eq!(counts(&root), (1, 0));
        std::fs::write(root.join("reject"), "").unwrap();
        std::fs::remove_file(root.join("block")).unwrap();
        assert!(!finish(first).status.success());
        assert_eq!(counts(&root), (1, 0));
    } else {
        let result = run(&["sync", "--reauth"], true);
        assert!(!String::from_utf8_lossy(&result.stdout).contains(SECRET));
        assert!(!String::from_utf8_lossy(&result.stderr).contains(SECRET));
        if scenario == "success" || scenario == "totp-success" {
            success(&result);
            assert_eq!(
                counts(&root),
                (1, if scenario == "totp-success" { 2 } else { 1 })
            );
            decrypt(&new.cipher, "fixture-22", None);
            decrypt(&new.org_cipher, "org-fixture-22", Some("fixture-org"));
            let saved = Db::load(&server, EMAIL).unwrap();
            assert_eq!(
                saved.refresh_token.as_deref(),
                Some("candidate-refresh")
            );
            assert_eq!(
                saved.protected_key.as_deref(),
                Some(new.protected.as_str())
            );
            assert_eq!(
                saved.protected_private_key.as_deref(),
                Some(new.private.as_str())
            );
            assert_eq!(saved.protected_org_keys["fixture-org"], new.org);
            assert_eq!(saved.entries.len(), 1);
            assert_eq!(saved.entries[0].id, "new-entry");
            assert_eq!(
                saved.entries[0].notes.as_deref(),
                Some(new.cipher.as_str())
            );
            mock.lock().unwrap().scenario = "rotate".into();
            success(&run(&["sync"], false));
            assert_eq!(
                mock.lock().unwrap().refreshes,
                ["old-refresh", "candidate-refresh"]
            );
            assert_eq!(
                Db::load(&server, EMAIL).unwrap().refresh_token.as_deref(),
                Some("rotated-refresh")
            );
            assert_eq!(
                counts(&root),
                (1, if scenario == "totp-success" { 2 } else { 1 })
            );
        } else {
            assert!(!result.status.success(), "{result:?}");
            let no_recovery = scenario.starts_with("initial-")
                || scenario.starts_with("refresh-");
            assert_eq!(
                counts(&root),
                (
                    usize::from(!no_recovery),
                    match scenario.as_str() {
                        _ if no_recovery => 0,
                        "reject" => 0,
                        "wrong-password" | "login-injected-error" => 3,
                        "totp-failure" => 2,
                        _ => 1,
                    }
                )
            );
        }
    }
    if !matches!(
        scenario.as_str(),
        "success"
            | "totp-success"
            | "locked-success"
            | "expired-success"
            | "sync-race"
    ) {
        assert_eq!(
            std::fs::read(rbw::dirs::db_file(&server, EMAIL)).unwrap(),
            original
        );
        decrypt(&old.cipher, "fixture-11", None);
        decrypt(&old.org_cipher, "org-fixture-11", Some("fixture-org"));
    }
    assert!(agent.0.try_wait().unwrap().is_none());
    assert!(!std::fs::read_to_string(root.join("agent.stderr"))
        .unwrap()
        .contains(SECRET));
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
}

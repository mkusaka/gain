// Run `gh` with a GitHub App installation token in GH_TOKEN. macOS only.
// Private keys live only inside `gain agent`, encrypted at rest with a passphrase; clients get tokens.
// Usage: gain agent start | unlock | lock | stop | status | install | uninstall (launchd) | reset
//        gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE
//        gain [--profile NAME] <gh args...>   e.g. gain --profile work pr list -R org/repo
//        gain [--profile NAME] token [--min-ttl MINUTES]   print the token (for curl, scripts, ...)
//        gain [--profile NAME] revoke         revoke the cached token (e.g. after it leaked)
//        gain [--profile NAME] credential get git credential helper (see README)
//        gain profile list | gain profile remove NAME
//        gain migrate-keychain                move profiles from gain <= 0.3's Keychain items
// Profile defaults to $GH_APP_PROFILE, then "default".
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, exit};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

type R<T> = Result<T, String>;

const LABEL: &str = "com.github.mkusaka.gain.agent";
// Set by the release build (GAIN_VERSION=x.y.z cargo build); "dev" when built from a clone.
const VERSION: &str = match option_env!("GAIN_VERSION") {
    Some(v) => v,
    None => "dev",
};
const SETUP_USAGE: &str =
    "gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE";
const AGENT_OPS: [&str; 8] = [
    "start",
    "unlock",
    "lock",
    "stop",
    "status",
    "install",
    "uninstall",
    "reset",
];

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}
fn dir() -> PathBuf {
    home().join(".local/share/gain")
}
fn vault_path() -> PathBuf {
    dir().join("vault")
}
fn socket_path() -> PathBuf {
    dir().join("agent.sock")
}
fn plist_path() -> PathBuf {
    home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    client_id: String,
    installation_id: String,
    private_key: Zeroizing<String>,
}

#[derive(Deserialize)]
struct Cached {
    token: Zeroizing<String>,
    expires_at: String,
}

// Vault: AES-256-GCM over the profiles JSON, key from the passphrase via scrypt (~0.3s, 128 MiB).
fn derive_key(passphrase: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = scrypt::Params::new(17, 8, 1).expect("valid scrypt params");
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key[..]).expect("32-byte output");
    key
}

fn aead(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("32-byte key"))
}

fn seal(key: &[u8; 32], salt: &[u8], profiles: &BTreeMap<String, Config>) -> String {
    let mut iv = [0u8; 12];
    SystemRandom::new().fill(&mut iv).expect("random iv");
    let plain = Zeroizing::new(serde_json::to_vec(profiles).expect("profiles serialize"));
    // Room for the tag up front: a reallocation would leave a plaintext copy behind.
    let mut buf = Vec::with_capacity(12 + plain.len() + 16);
    buf.extend_from_slice(&iv);
    buf.extend_from_slice(&plain);
    let mut body = buf.split_off(12);
    aead(key)
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(iv), Aad::empty(), &mut body)
        .expect("seal");
    buf.extend_from_slice(&body);
    json!({ "salt": STANDARD.encode(salt), "data": STANDARD.encode(&buf) }).to_string()
}

fn unseal(key: &[u8; 32], data: &[u8]) -> R<BTreeMap<String, Config>> {
    if data.len() < 28 {
        return Err("wrong passphrase".into());
    }
    let iv: [u8; 12] = data[..12].try_into().unwrap();
    let mut buf = Zeroizing::new(data[12..].to_vec());
    let plain = aead(key)
        .open_in_place(Nonce::assume_unique_for_key(iv), Aad::empty(), &mut buf)
        .map_err(|_| "wrong passphrase".to_string())?;
    serde_json::from_slice(plain).map_err(|e| format!("corrupt vault: {e}"))
}

// Profile names: keep them to safe characters (also used in the old Keychain item names).
fn check_profile_name(name: Option<&Value>) -> R<String> {
    match name.and_then(Value::as_str) {
        Some(s) if is_profile_name(s) => Ok(s.to_string()),
        _ => Err("profile names must match [A-Za-z0-9_.-]+".into()),
    }
}
fn is_profile_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn b64url(s: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(s)
}

// GitHub hands out PKCS#1 PEMs ("RSA PRIVATE KEY"); PKCS#8 ("PRIVATE KEY") works too.
fn parse_key(pem: &str) -> R<RsaKeyPair> {
    let bad = || "the private key must be an RSA key in PEM format".to_string();
    let begin = pem.find("-----BEGIN ").ok_or_else(bad)?;
    let rest = &pem[begin + 11..];
    let label_end = rest.find("-----").ok_or_else(bad)?;
    let label = &rest[..label_end];
    let body = &rest[label_end + 5..];
    let end = body.find("-----END ").ok_or_else(bad)?;
    let b64 = Zeroizing::new(
        body[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    let der = Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| bad())?);
    match label {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
        _ => return Err(bad()),
    }
    .map_err(|e| format!("invalid private key: {e}"))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn create_jwt(client_id: &str, private_key: &str, now: i64) -> R<String> {
    let key = parse_key(private_key)?;
    // GitHub rejects exp more than 10 minutes out; iat is backdated for clock skew.
    let body = format!(
        "{}.{}",
        b64url(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64url(
            json!({ "iat": now - 60, "exp": now + 540, "iss": client_id })
                .to_string()
                .as_bytes()
        )
    );
    let mut sig = vec![0u8; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        body.as_bytes(),
        &mut sig,
    )
    .map_err(|_| "signing failed".to_string())?;
    Ok(format!("{body}.{}", b64url(&sig)))
}

// "2026-01-01T00:10:00Z" (what GitHub returns) -> Unix ms.
fn parse_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Some(((days * 24 + hh) * 60 + mm) * 60_000 + ss * 1000)
}

// Minutes of headroom so long-running commands (e.g. `gh run watch`) don't outlive the token.
fn is_fresh(c: Option<&Cached>, min_ttl: f64, now_ms: i64) -> bool {
    c.and_then(|c| parse_time(&c.expires_at))
        .is_some_and(|exp| (exp - now_ms) as f64 > min_ttl * 60_000.0)
}

// git credential protocol: key=value lines on stdin. Only answer for https://github.com.
fn is_github_https(request: &str) -> bool {
    let (mut protocol, mut host) = (None, None);
    for (k, v) in request.split('\n').filter_map(|l| l.split_once('=')) {
        match k {
            "protocol" => protocol = Some(v),
            "host" => host = Some(v),
            _ => {}
        }
    }
    protocol == Some("https") && host == Some("github.com")
}

fn github(method: &str, path: &str, bearer: &str) -> R<(u16, Zeroizing<String>)> {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        // The agent serves other clients meanwhile, but a hung request would pin its profile.
        .timeout_global(Some(Duration::from_secs(30)))
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::NativeTls)
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent();
    let url = format!("https://api.github.com{path}");
    let auth = Zeroizing::new(format!("Bearer {bearer}"));
    let req = ureq::http::Request::builder()
        .method(method)
        .uri(&url)
        .header("Authorization", auth.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "gain")
        .body("")
        .map_err(|e| e.to_string())?;
    let mut res = agent
        .run(req)
        .map_err(|e| format!("{method} {url} failed: {e}"))?;
    let status = res.status().as_u16();
    let body = Zeroizing::new(res.body_mut().read_to_string().map_err(|e| e.to_string())?);
    Ok((status, body))
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
    account: Account,
}
#[derive(Deserialize)]
struct Account {
    login: String,
}

fn pick_installation(installations: &[Installation]) -> R<String> {
    match installations {
        [one] => Ok(one.id.to_string()),
        [] => Err("the App is not installed anywhere; install it first".into()),
        many => {
            let list: Vec<_> = many
                .iter()
                .map(|i| format!("{} ({})", i.id, i.account.login))
                .collect();
            Err(format!(
                "the App has several installations; pass --installation-id: {}",
                list.join(", ")
            ))
        }
    }
}

fn find_installation_id(client_id: &str, private_key: &str) -> R<String> {
    let jwt = create_jwt(client_id, private_key, now_secs())?;
    let (status, body) = github("GET", "/app/installations?per_page=100", &jwt)?;
    if !(200..300).contains(&status) {
        return Err(format!("installation lookup failed: {status} {}", *body));
    }
    pick_installation(&serde_json::from_str::<Vec<Installation>>(&body).map_err(|e| e.to_string())?)
}

fn fetch_token(c: &Config) -> R<Cached> {
    let jwt = create_jwt(&c.client_id, &c.private_key, now_secs())?;
    let path = format!("/app/installations/{}/access_tokens", c.installation_id);
    let (status, body) = github("POST", &path, &jwt)?;
    if !(200..300).contains(&status) {
        return Err(format!("token request failed: {status} {}", *body));
    }
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

// What a client sends: one JSON object per connection.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Request {
    cmd: String,
    passphrase: Option<Zeroizing<String>>,
    profile: Option<Value>,
    min_ttl: Option<f64>,
    config: Option<SetupRequest>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupRequest {
    client_id: Value,
    installation_id: Option<Value>,
    private_key: Zeroizing<String>,
}

// Client IDs and installation IDs may arrive as JSON numbers (gain <= 0.3 Keychain items).
fn id_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

// Holds the decrypted profiles while unlocked. No request returns a private key.
// Tokens are cached in memory only, so a restart or lock just mints new ones.
// Key, private keys and tokens are zeroized when dropped (lock, remove, replace).
struct Agent {
    key: Option<Zeroizing<[u8; 32]>>,
    salt: Vec<u8>,
    profiles: BTreeMap<String, Config>,
    tokens: HashMap<String, Cached>,
    vault: PathBuf,
}

impl Agent {
    fn new(vault: PathBuf) -> Self {
        Agent {
            key: None,
            salt: vec![],
            profiles: BTreeMap::new(),
            tokens: HashMap::new(),
            vault,
        }
    }

    fn unlock(&mut self, passphrase: &str) -> R<()> {
        if self.key.is_some() {
            return Ok(());
        }
        if self.vault.exists() {
            let text = fs::read_to_string(&self.vault).map_err(|e| e.to_string())?;
            let v: Value =
                serde_json::from_str(&text).map_err(|e| format!("corrupt vault: {e}"))?;
            let field = |k: &str| {
                v[k].as_str()
                    .and_then(|s| STANDARD.decode(s).ok())
                    .ok_or_else(|| format!("corrupt vault: no {k}"))
            };
            let (salt, data) = (field("salt")?, field("data")?);
            let key = derive_key(passphrase, &salt);
            self.profiles = unseal(&key, &data)?;
            (self.key, self.salt) = (Some(key), salt);
        } else {
            let mut salt = vec![0u8; 16];
            SystemRandom::new().fill(&mut salt).expect("random salt");
            self.key = Some(derive_key(passphrase, &salt));
            self.salt = salt;
            self.save()?;
        }
        Ok(())
    }

    fn lock(&mut self) {
        self.key = None;
        self.profiles.clear();
        self.tokens.clear();
    }

    fn save(&self) -> R<()> {
        let tmp = self.vault.with_extension("tmp");
        let sealed = seal(self.key.as_ref().unwrap(), &self.salt, &self.profiles);
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(sealed.as_bytes()))
            .and_then(|_| fs::rename(&tmp, &self.vault))
            .map_err(|e| format!("saving {}: {e}", self.vault.display()))
    }

    fn token(&mut self, profile: &str, min_ttl: f64) -> R<String> {
        let cached = self.tokens.get(profile);
        if is_fresh(cached, min_ttl, now_secs() * 1000) {
            return Ok(cached.unwrap().token.to_string());
        }
        let config = self
            .profiles
            .get(profile)
            .ok_or_else(|| format!("profile \"{profile}\" not configured; run: {SETUP_USAGE}"))?;
        let fresh = fetch_token(config)?;
        let token = fresh.token.to_string();
        self.tokens.insert(profile.to_string(), fresh);
        Ok(token)
    }

    // Tokens already handed out earlier stay valid until they expire; this only revokes the cached one.
    fn revoke(&mut self, profile: &str) -> R<String> {
        let Some(cached) = self.tokens.get(profile) else {
            return Ok("no cached token".into());
        };
        if is_fresh(Some(cached), 0.0, now_secs() * 1000) {
            let (status, body) = github("DELETE", "/installation/token", &cached.token)?;
            // 401: already revoked or expired.
            if !(200..300).contains(&status) && status != 401 {
                return Err(format!("revoke failed: {status} {}", *body));
            }
        }
        self.tokens.remove(profile);
        Ok("revoked the cached token".into())
    }

    fn setup(&mut self, profile: &str, c: SetupRequest) -> R<String> {
        let client_id = id_string(&c.client_id).ok_or("setup needs a client ID")?;
        let installation_id = match c.installation_id.as_ref().and_then(id_string) {
            Some(id) => id,
            None => find_installation_id(&client_id, &c.private_key)?,
        };
        let config = Config {
            client_id,
            installation_id: installation_id.clone(),
            private_key: c.private_key,
        };
        let token = fetch_token(&config)?; // verify before saving
        self.profiles.insert(profile.to_string(), config);
        self.save()?;
        self.tokens.insert(profile.to_string(), token);
        Ok(installation_id)
    }

    fn handle(&mut self, req: Request) -> R<Map<String, Value>> {
        let ok = |v: Value| Ok(v.as_object().cloned().unwrap_or_default());
        match req.cmd.as_str() {
            "status" => return ok(json!({ "unlocked": self.key.is_some(), "version": VERSION })),
            "lock" => {
                self.lock();
                return ok(json!({}));
            }
            "unlock" => {
                let pass = req.passphrase.ok_or("no passphrase")?;
                return self.unlock(&pass).and_then(|_| ok(json!({})));
            }
            _ => {}
        }
        if self.key.is_none() {
            return Err("the agent is locked; run: gain agent unlock".into());
        }
        if req.cmd == "list" {
            return ok(json!({ "profiles": self.profiles.keys().collect::<Vec<_>>() }));
        }
        let profile = check_profile_name(req.profile.as_ref())?;
        match req.cmd.as_str() {
            "token" => ok(json!({ "token": self.token(&profile, req.min_ttl.unwrap_or(5.0))? })),
            "revoke" => ok(json!({ "message": self.revoke(&profile)? })),
            "setup" => {
                let c = req.config.ok_or("setup needs a config")?;
                ok(json!({ "installationId": self.setup(&profile, c)? }))
            }
            "remove" => {
                if self.profiles.remove(&profile).is_none() {
                    return Err(format!("profile \"{profile}\" not found"));
                }
                self.tokens.remove(&profile);
                self.save()?;
                ok(json!({}))
            }
            cmd => Err(format!("unknown command: {cmd}")),
        }
    }
}

// One JSON request line per connection, one JSON response line back.
fn call(req: Value) -> R<Map<String, Value>> {
    let mut sock = UnixStream::connect(socket_path()).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            "the agent is not running; start it with: gain agent start".to_string()
        }
        _ => e.to_string(),
    })?;
    let line = Zeroizing::new(format!("{req}\n"));
    sock.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    sock.read_to_string(&mut out).map_err(|e| e.to_string())?;
    if out.is_empty() {
        return Err("the agent closed the connection".into());
    }
    let res: Map<String, Value> = serde_json::from_str(&out).map_err(|e| e.to_string())?;
    match res.get("error") {
        Some(e) => Err(e.as_str().unwrap_or("unknown error").to_string()),
        None => Ok(res),
    }
}

// Mach-O code signature of this binary: hardened runtime on, nothing that lets another
// same-user process attach a debugger or inject a library (README "Why Rust").
fn check_hardened(info: &str) -> bool {
    let runtime = info
        .split("flags=0x")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .is_some_and(|flags| flags.contains("runtime"));
    runtime
        && ![
            "get-task-allow",
            "allow-dyld-environment-variables",
            "disable-library-validation",
        ]
        .iter()
        .any(|e| info.contains(e))
}

fn start_agent() -> R<()> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let sig = Command::new("codesign")
        .args(["-dv", "--entitlements", "-"])
        .arg(&exe)
        .output()
        .map_err(|e| format!("codesign: {e}"))?;
    let info = format!(
        "{}{}",
        String::from_utf8_lossy(&sig.stdout),
        String::from_utf8_lossy(&sig.stderr)
    );
    if !check_hardened(&info) {
        return Err(format!(
            "{} allows debugger attach; sign it with the hardened runtime: codesign -s - -f -o runtime {0}",
            exe.display()
        ));
    }
    let dir = dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let sock = socket_path();
    if sock.exists() {
        if call(json!({ "cmd": "status" })).is_ok() {
            return Err("another agent is already running".into());
        }
        fs::remove_file(&sock).map_err(|e| e.to_string())?;
    }
    unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&sock).map_err(|e| e.to_string())?;
    // Remove the socket on SIGINT/SIGTERM/SIGHUP: block them everywhere, wait for them on one thread.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        let sock = sock.clone();
        std::thread::spawn(move || {
            let mut sig = 0;
            libc::sigwait(&set, &mut sig);
            let _ = fs::remove_file(&sock);
            exit(0);
        });
    }
    eprintln!("gain: agent listening on {} (locked)", sock.display());
    let agent = Arc::new(Mutex::new(Agent::new(vault_path())));
    for conn in listener.incoming().flatten() {
        let (agent, sock) = (agent.clone(), sock.clone());
        std::thread::spawn(move || serve(conn, &agent, &sock));
    }
    Ok(())
}

fn serve(mut conn: UnixStream, agent: &Mutex<Agent>, sock: &Path) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let mut line = Zeroizing::new(Vec::new());
    let mut reader = BufReader::new((&conn).take(65_536));
    if reader.read_until(b'\n', &mut line).is_err() || line.last() != Some(&b'\n') {
        return;
    }
    let res = match serde_json::from_slice::<Request>(&line) {
        Ok(req) if req.cmd == "stop" => {
            let _ = conn.write_all(b"{\"ok\":true}\n");
            let _ = fs::remove_file(sock);
            exit(0);
        }
        Ok(req) => {
            let mut agent = agent.lock().unwrap_or_else(|e| e.into_inner());
            agent.handle(req)
        }
        Err(e) => Err(e.to_string()),
    };
    let body = match res {
        Ok(mut m) => {
            m.insert("ok".into(), Value::Bool(true));
            Value::Object(m)
        }
        Err(e) => json!({ "error": e }),
    };
    let out = Zeroizing::new(format!("{body}\n"));
    let _ = conn.write_all(out.as_bytes());
}

// Read from the terminal (never a pipe), without echo unless `echo`; `read -s` restores the tty even on Ctrl-C.
fn read_tty(prompt: &str, echo: bool) -> R<Zeroizing<String>> {
    let read = if echo {
        r#"read -rp "$1" s </dev/tty && printf %s "$s""#
    } else {
        r#"read -rsp "$1" s </dev/tty && echo >/dev/tty && printf %s "$s""#
    };
    let out = Command::new("/bin/bash")
        .args(["-c", read, "gain", prompt])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("no input from the terminal".into());
    }
    let s = Zeroizing::new(out.stdout);
    Ok(Zeroizing::new(String::from_utf8_lossy(&s).into_owned()))
}

// launchd runs the agent at login (and right away). No KeepAlive: a restarted agent is locked
// anyway, and a broken path (gain moved) would make launchd retry it every 10 seconds.
fn launchd_plist(args: &[String], log: &str) -> String {
    let esc = |v: &str| v.replace('&', "&amp;").replace('<', "&lt;");
    let program: String = args
        .iter()
        .map(|a| format!("<string>{}</string>", esc(a)))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array>{program}</array>
  <key>RunAtLoad</key><true/>
  <key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
        esc(log)
    )
}

fn launchctl(args: &[&str]) -> std::process::Output {
    Command::new("launchctl")
        .args(args)
        .output()
        .expect("launchctl")
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

// An npm install lives under node_modules, which switching Node versions (nvm, mise, ...) or
// clearing npx's cache deletes, leaving launchd a missing file: run a copy next to the vault.
// Replaced by rename, never overwritten in place, so a running copy keeps a valid signature.
fn stable_copy(me: &Path, dir: &Path) -> R<PathBuf> {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let (tmp, copy) = (bin.join("gain.tmp"), bin.join("gain"));
    fs::copy(me, &tmp)
        .and_then(|_| fs::rename(&tmp, &copy))
        .map_err(|e| format!("copying {} to {}: {e}", me.display(), copy.display()))?;
    Ok(copy)
}

fn install_agent() -> R<String> {
    launchctl(&["bootout", &format!("gui/{}/{LABEL}", uid())]); // replace an older install
    if call(json!({ "cmd": "status" })).is_ok() {
        return Err("an agent is already running; stop it first: gain agent stop".into());
    }
    // Absolute path: launchd has no PATH to speak of. Prefer the `gain` on PATH when it is this
    // binary (e.g. Homebrew's /opt/homebrew/bin/gain link): the versioned Caskroom path changes on upgrade.
    let me = fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let on_path = Command::new("/bin/sh")
        .args(["-c", "command -v gain"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let program = if me.components().any(|c| c.as_os_str() == "node_modules") {
        stable_copy(&me, &dir())?.display().to_string()
    } else if !on_path.is_empty() && fs::canonicalize(&on_path).ok().as_ref() == Some(&me) {
        on_path
    } else {
        me.display().to_string()
    };
    let log = home().join("Library/Logs/gain-agent.log");
    let plist = plist_path();
    fs::create_dir_all(plist.parent().unwrap()).map_err(|e| e.to_string())?;
    let args = [program, "agent".into(), "start".into()];
    fs::write(&plist, launchd_plist(&args, &log.display().to_string()))
        .map_err(|e| e.to_string())?;
    let r = launchctl(&[
        "bootstrap",
        &format!("gui/{}", uid()),
        &plist.display().to_string(),
    ]);
    if !r.status.success() {
        return Err(format!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&r.stderr)
        ));
    }
    Ok(format!(
        "installed {}; the agent starts at login (log: {}). Now run: gain agent unlock",
        plist.display(),
        log.display()
    ))
}

fn uninstall_agent() -> String {
    launchctl(&["bootout", &format!("gui/{}/{LABEL}", uid())]);
    let plist = plist_path();
    let _ = fs::remove_file(&plist);
    let _ = fs::remove_dir_all(dir().join("bin")); // the copy an npm install runs (stable_copy)
    format!("removed {} and stopped the agent", plist.display())
}

// A brew upgrade doesn't restart the agent, so it may still run the previous binary.
fn status_line(res: &Map<String, Value>, client: &str) -> String {
    let unlocked = res
        .get("unlocked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let version = res.get("version").and_then(Value::as_str);
    let state = format!(
        "{} (agent {})",
        if unlocked { "unlocked" } else { "locked" },
        version.unwrap_or("unknown")
    );
    if version == Some(client) {
        return state;
    }
    format!("{state}; this gain is {client}, restart the agent to update it: gain agent install")
}

fn unlock_agent() -> R<String> {
    if call(json!({ "cmd": "status" }))?.get("unlocked") == Some(&Value::Bool(true)) {
        return Ok("already unlocked".into());
    }
    let vault = vault_path();
    if vault.exists() {
        let passphrase = read_tty("gain passphrase: ", false)?;
        call(json!({ "cmd": "unlock", "passphrase": passphrase.as_str() }))?;
        return Ok("unlocked".into());
    }
    let passphrase = read_tty("new gain passphrase (min 12 chars): ", false)?;
    if passphrase.chars().count() < 12 {
        return Err("passphrase too short".into());
    }
    if *read_tty("again: ", false)? != *passphrase {
        return Err("passphrases don't match".into());
    }
    call(json!({ "cmd": "unlock", "passphrase": passphrase.as_str() }))?;
    Ok(format!(
        "created {} and unlocked; if you forget the passphrase: gain agent reset",
        vault.display()
    ))
}

// For a forgotten passphrase: the vault is the only copy of the keys, so this can't be undone.
fn reset_agent() -> R<String> {
    let vault = vault_path();
    if !vault.exists() {
        return Ok("no vault; nothing to reset".into());
    }
    let answer = read_tty(
        &format!(
            "Delete {}? Every profile's private key in it is lost for good. Type \"reset\" to confirm: ",
            vault.display()
        ),
        true,
    )?;
    if answer.as_str() != "reset" {
        return Err("aborted".into());
    }
    // Drop the decrypted keys a running agent may hold; it stays up, locked.
    let _ = call(json!({ "cmd": "lock" }));
    fs::remove_file(&vault).map_err(|e| e.to_string())?;
    Ok("deleted the vault. Next: gain agent unlock (new passphrase), then gain setup with a new private key per profile".into())
}

// Keychain items written by gain <= 0.3: service "gain", accounts config:<p> and token:<p>.
fn list_profiles(dump: &str) -> Vec<String> {
    let mut out: Vec<String> = format!("\n{dump}")
        .split("\nkeychain: ")
        .filter(|item| item.contains(r#""svce"<blob>="gain""#))
        .filter_map(|item| {
            let rest = item.split(r#""acct"<blob>="config:"#).nth(1)?;
            let (name, _) = rest.split_once('"')?;
            is_profile_name(name).then(|| name.to_string())
        })
        .collect();
    out.sort();
    out
}

fn migrate_keychain() -> R<String> {
    let security = |args: &[&str]| {
        Command::new("security")
            .args(args)
            .output()
            .map_err(|e| format!("security: {e}"))
    };
    let dump = security(&["dump-keychain"])?;
    if !dump.status.success() {
        return Err(format!(
            "keychain list failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        ));
    }
    let profiles = list_profiles(&String::from_utf8_lossy(&dump.stdout));
    if profiles.is_empty() {
        return Ok("nothing to migrate".into());
    }
    for profile in profiles {
        let acct = format!("config:{profile}");
        let r = security(&["find-generic-password", "-s", "gain", "-a", &acct, "-w"])?;
        if !r.status.success() {
            return Err(format!(
                "keychain read failed: {}",
                String::from_utf8_lossy(&r.stderr)
            ));
        }
        let b64 = Zeroizing::new(r.stdout);
        let raw = Zeroizing::new(
            STANDARD
                .decode(String::from_utf8_lossy(&b64).trim())
                .map_err(|e| e.to_string())?,
        );
        let config: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        call(json!({ "cmd": "setup", "profile": profile, "config": config }))?;
        // The point of migrating: no copy of the key may stay where any process can read it.
        for acct in [format!("config:{profile}"), format!("token:{profile}")] {
            let d = security(&["delete-generic-password", "-s", "gain", "-a", &acct])?;
            if !d.status.success() && d.status.code() != Some(44) {
                return Err(format!(
                    "migrated \"{profile}\" but failed to delete Keychain item {acct}: {}",
                    String::from_utf8_lossy(&d.stderr)
                ));
            }
        }
        eprintln!("gain: migrated profile \"{profile}\" and deleted its Keychain items");
    }
    Ok("migrated".into())
}

#[derive(Debug, PartialEq)]
enum Cli {
    Agent(String),
    MigrateKeychain,
    ProfileList,
    ProfileRemove(String),
    Run { profile: String, cmd: Cmd },
}

#[derive(Debug, PartialEq)]
enum Cmd {
    Setup {
        client_id: String,
        installation_id: Option<String>,
        key_path: String,
    },
    Token {
        min_ttl: i64,
    },
    Revoke,
    Credential(String),
    Gh(Vec<String>),
}

// `--name VALUE` or `--name=VALUE` at args[i]; returns the value and how many args it used.
fn opt_value(args: &[String], i: usize, name: &str) -> R<Option<(String, usize)>> {
    let a = &args[i];
    if let Some(v) = a.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
        return Ok(Some((v.to_string(), 1)));
    }
    if a != name {
        return Ok(None);
    }
    match args.get(i + 1) {
        Some(v) => Ok(Some((v.clone(), 2))),
        None => Err(format!("{name} needs a value")),
    }
}

// Anything that isn't a gain command goes to gh untouched, so gain has no --help/--version of its own.
fn parse(args: &[String], env_profile: Option<String>) -> R<Cli> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["agent", op] if AGENT_OPS.contains(op) => return Ok(Cli::Agent(op.to_string())),
        ["agent", ..] => return Err(format!("usage: gain agent {}", AGENT_OPS.join("|"))),
        ["migrate-keychain"] => return Ok(Cli::MigrateKeychain),
        ["profile", "list"] => return Ok(Cli::ProfileList),
        ["profile", "remove", name] => return Ok(Cli::ProfileRemove(name.to_string())),
        ["profile", ..] => return Err("usage: gain profile list | gain profile remove NAME".into()),
        _ => {}
    }
    let mut profile = env_profile
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "default".into());
    let mut rest = args;
    if !args.is_empty()
        && let Some((p, n)) = opt_value(args, 0, "--profile")?
    {
        profile = p;
        rest = &args[n..];
    }
    let r: Vec<&str> = rest.iter().map(String::as_str).collect();
    let cmd = match r.as_slice() {
        ["setup", ..] => {
            let (mut client_id, mut installation_id, mut key_path) = (None, None, None);
            let mut i = 1;
            while i < rest.len() {
                let mut hit = false;
                for (name, slot) in [
                    ("--client-id", &mut client_id),
                    ("--installation-id", &mut installation_id),
                    ("--private-key-path", &mut key_path),
                ] {
                    if let Some((v, n)) = opt_value(rest, i, name)? {
                        (*slot, i, hit) = (Some(v), i + n, true);
                        break;
                    }
                }
                if !hit {
                    return Err(format!("unexpected {}; usage: {SETUP_USAGE}", rest[i]));
                }
            }
            match (client_id, key_path) {
                (Some(client_id), Some(key_path)) => Cmd::Setup {
                    client_id,
                    installation_id,
                    key_path,
                },
                _ => return Err(format!("usage: {SETUP_USAGE}")),
            }
        }
        ["token"] => Cmd::Token { min_ttl: 5 },
        ["token", ..] => {
            let usage = "usage: gain [--profile NAME] token [--min-ttl MINUTES]";
            match opt_value(rest, 1, "--min-ttl")? {
                Some((v, n)) if 1 + n == rest.len() => {
                    // Installation tokens live 60 minutes, so more headroom than that can never be met.
                    match v.parse::<i64>() {
                        Ok(m) if (0..=60).contains(&m) => Cmd::Token { min_ttl: m },
                        _ => return Err(format!("--min-ttl must be 0-60 minutes, got {v:?}")),
                    }
                }
                _ => return Err(usage.into()),
            }
        }
        ["revoke"] => Cmd::Revoke,
        ["credential", op] if ["get", "store", "erase"].contains(op) => {
            Cmd::Credential(op.to_string())
        }
        ["credential", ..] => return Err("usage: gain credential get|store|erase".into()),
        _ => Cmd::Gh(rest.to_vec()),
    };
    Ok(Cli::Run { profile, cmd })
}

fn done(msg: &str) -> ! {
    eprintln!("gain: {msg}");
    exit(0)
}

fn token_of(res: &Map<String, Value>) -> Zeroizing<String> {
    Zeroizing::new(
        res.get("token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

fn run(args: Vec<String>) -> R<()> {
    match parse(&args, std::env::var("GH_APP_PROFILE").ok())? {
        Cli::Agent(op) => match op.as_str() {
            "start" => start_agent(),
            "unlock" => done(&unlock_agent()?),
            "install" => done(&install_agent()?),
            "uninstall" => done(&uninstall_agent()),
            "reset" => done(&reset_agent()?),
            "status" => done(&status_line(&call(json!({ "cmd": "status" }))?, VERSION)),
            _ => {
                call(json!({ "cmd": op }))?;
                done(&format!(
                    "agent {}",
                    if op == "stop" { "stopped" } else { "locked" }
                ))
            }
        },
        Cli::MigrateKeychain => done(&migrate_keychain()?),
        Cli::ProfileList => {
            let res = call(json!({ "cmd": "list" }))?;
            for p in res["profiles"].as_array().into_iter().flatten() {
                println!("{}", p.as_str().unwrap_or_default());
            }
            Ok(())
        }
        Cli::ProfileRemove(name) => {
            let profile = check_profile_name(Some(&Value::String(name)))?;
            call(json!({ "cmd": "remove", "profile": profile }))?;
            done(&format!("removed profile \"{profile}\""))
        }
        Cli::Run { profile, cmd } => {
            let profile = check_profile_name(Some(&Value::String(profile)))?;
            match cmd {
                Cmd::Setup {
                    client_id,
                    installation_id,
                    key_path,
                } => {
                    let private_key = Zeroizing::new(
                        fs::read_to_string(&key_path).map_err(|e| format!("{key_path}: {e}"))?,
                    );
                    let res = call(json!({
                        "cmd": "setup",
                        "profile": profile,
                        "config": { "clientId": client_id, "installationId": installation_id, "privateKey": private_key.as_str() },
                    }))?;
                    let id = res
                        .get("installationId")
                        .map(|v| id_string(v).unwrap_or_default());
                    done(&format!(
                        "saved profile \"{profile}\" (installation {}) to the agent's vault. You can now delete {key_path}.",
                        id.unwrap_or_default()
                    ))
                }
                Cmd::Token { min_ttl } => {
                    let res =
                        call(json!({ "cmd": "token", "profile": profile, "minTtl": min_ttl }))?;
                    println!("{}", *token_of(&res));
                    Ok(())
                }
                Cmd::Revoke => {
                    let res = call(json!({ "cmd": "revoke", "profile": profile }))?;
                    done(res.get("message").and_then(Value::as_str).unwrap_or(""))
                }
                Cmd::Credential(op) => {
                    // store/erase are no-ops; the agent owns the token.
                    if op == "get" {
                        let mut input = String::new();
                        std::io::stdin()
                            .read_to_string(&mut input)
                            .map_err(|e| e.to_string())?;
                        if is_github_https(&input) {
                            let res = call(json!({ "cmd": "token", "profile": profile }))?;
                            println!("username=x-access-token\npassword={}", *token_of(&res));
                        }
                    }
                    Ok(())
                }
                Cmd::Gh(args) => {
                    let res = call(json!({ "cmd": "token", "profile": profile }))?;
                    let status = Command::new("gh")
                        .args(&args)
                        .env("GH_TOKEN", token_of(&res).as_str())
                        .status();
                    match status {
                        Err(e) => {
                            eprintln!("gain: failed to run gh: {e}");
                            exit(127)
                        }
                        // Killed by a signal: no code; exit 128+signo like a shell.
                        Ok(s) => exit(s.code().unwrap_or(128 + s.signal().unwrap_or(0))),
                    }
                }
            }
        }
    }
}

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("gain: {e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }
    fn tmp_vault() -> PathBuf {
        let mut salt = [0u8; 8];
        SystemRandom::new().fill(&mut salt).unwrap();
        let d = std::env::temp_dir().join(format!("gain-test-{}", URL_SAFE_NO_PAD.encode(salt)));
        fs::create_dir_all(&d).unwrap();
        d.join("vault")
    }
    fn req(v: Value) -> Request {
        serde_json::from_value(v).unwrap()
    }
    fn config(key: &str) -> Config {
        Config {
            client_id: "c".into(),
            installation_id: "1".into(),
            private_key: Zeroizing::new(key.into()),
        }
    }

    // Sealed by gain 0.4.2 (gain.ts) with passphrase "fixture-passphrase": existing vaults must open.
    const TS_VAULT: &str = r#"{"salt":"ABEiM0RVZneImaq7zN3u/w==","data":"ZXB53sW7KhjoAO9kGd1S2A3GeOslC0CfcABH6gKMIu9dyNISN8OS07EZND8+I6yr38RFUszEGBKU920asuAFRY57h2n8W61uyeIzs9f2ReAos0AHzdyzUG+Fz11TzkUM14xbajl6oWnM8iCUI8xhk1R/SIYixvlaTtyzxNeUTLa9wzJZm0+GqdjBvnzSw81SXw6KmPsYV7V0FckHqacTqBJCQWm5JqOR8JTgV4Tb"}"#;

    #[test]
    fn opens_a_vault_sealed_by_the_typescript_version() {
        let vault = tmp_vault();
        fs::write(&vault, TS_VAULT).unwrap();
        let mut agent = Agent::new(vault);
        assert_eq!(agent.unlock("wrong").unwrap_err(), "wrong passphrase");
        agent.unlock("fixture-passphrase").unwrap();
        let work = &agent.profiles["work"];
        assert_eq!(
            (
                work.client_id.as_str(),
                work.installation_id.as_str(),
                work.private_key.as_str()
            ),
            ("Iv23liFIXTURE", "42", "pem")
        );
        assert_eq!(agent.profiles["default"].private_key.as_str(), "pem2");
    }

    #[test]
    fn vault_round_trips_and_rejects_a_wrong_passphrase() {
        let salt = [7u8; 16];
        let profiles = BTreeMap::from([("w".to_string(), config("pem"))]);
        let sealed: Value =
            serde_json::from_str(&seal(&derive_key("right", &salt), &salt, &profiles)).unwrap();
        let blob = STANDARD.decode(sealed["data"].as_str().unwrap()).unwrap();
        let back = unseal(&derive_key("right", &salt), &blob).unwrap();
        assert_eq!(back["w"].private_key.as_str(), "pem");
        assert_eq!(
            unseal(&derive_key("wrong", &salt), &blob).err().unwrap(),
            "wrong passphrase"
        );
    }

    #[test]
    fn agent_creates_the_vault_on_first_unlock_and_gates_everything_behind_it() {
        let vault = tmp_vault();
        let mut agent = Agent::new(vault.clone());
        let status = agent.handle(req(json!({ "cmd": "status" }))).unwrap();
        assert_eq!(
            Value::Object(status),
            json!({ "unlocked": false, "version": "dev" })
        );
        assert!(
            agent
                .handle(req(json!({ "cmd": "list" })))
                .unwrap_err()
                .contains("locked")
        );
        agent
            .handle(req(json!({ "cmd": "unlock", "passphrase": "pass" })))
            .unwrap();
        assert_eq!(
            fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let list = agent.handle(req(json!({ "cmd": "list" }))).unwrap();
        assert_eq!(Value::Object(list), json!({ "profiles": [] }));
        let err = agent.handle(req(json!({ "cmd": "token", "profile": "x" })));
        assert!(err.unwrap_err().contains("not configured"));
        let err = agent.handle(req(json!({ "cmd": "token", "profile": "../x" })));
        assert!(err.unwrap_err().contains("profile names"));
        let msg = agent
            .handle(req(json!({ "cmd": "revoke", "profile": "nope" })))
            .unwrap();
        assert_eq!(msg["message"], "no cached token");
        // A profile saved straight into the vault: the key never shows up in it, nor in any reply.
        agent.profiles.insert("w".into(), config("SECRET-PEM"));
        agent.save().unwrap();
        assert!(!fs::read_to_string(&vault).unwrap().contains("SECRET-PEM"));
        for cmd in ["status", "list"] {
            let res = agent.handle(req(json!({ "cmd": cmd }))).unwrap();
            assert!(!Value::Object(res).to_string().contains("SECRET-PEM"));
        }
        agent.handle(req(json!({ "cmd": "lock" }))).unwrap();
        assert!(agent.key.is_none() && agent.profiles.is_empty());
        let err = agent.handle(req(json!({ "cmd": "unlock", "passphrase": "nope" })));
        assert_eq!(err.unwrap_err(), "wrong passphrase");
        agent
            .handle(req(json!({ "cmd": "unlock", "passphrase": "pass" })))
            .unwrap();
        assert_eq!(agent.profiles["w"].private_key.as_str(), "SECRET-PEM");
        agent
            .handle(req(json!({ "cmd": "remove", "profile": "w" })))
            .unwrap();
        let err = agent.handle(req(json!({ "cmd": "remove", "profile": "w" })));
        assert_eq!(err.unwrap_err(), "profile \"w\" not found");
    }

    // Wraps a PKCS#1 RSAPrivateKey DER (what GitHub hands out) out of a PKCS#8 one.
    fn pkcs1_of(pkcs8: &[u8]) -> Vec<u8> {
        // SEQUENCE { INTEGER 0, SEQUENCE algid, OCTET STRING pkcs1 }
        let skip = |b: &[u8]| -> (usize, usize) {
            // (header length, content length)
            if b[1] < 0x80 {
                (2, b[1] as usize)
            } else {
                let n = (b[1] & 0x7f) as usize;
                (
                    2 + n,
                    b[2..2 + n].iter().fold(0, |a, &x| a << 8 | x as usize),
                )
            }
        };
        let (h, _) = skip(pkcs8);
        let mut b = &pkcs8[h..];
        for _ in 0..2 {
            let (h, l) = skip(b);
            b = &b[h + l..];
        }
        let (h, l) = skip(b);
        b[h..h + l].to_vec()
    }

    fn pem(label: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            STANDARD.encode(der)
        )
    }

    #[test]
    fn create_jwt_signs_pkcs1_and_pkcs8_keys_with_valid_claims() {
        let key = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let pkcs8 = key.as_der().unwrap();
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref());
        for pem in [
            pem("RSA PRIVATE KEY", &pkcs1_of(pkcs8.as_ref())),
            pem("PRIVATE KEY", pkcs8.as_ref()),
        ] {
            let jwt = create_jwt("123", &pem, 1000).unwrap();
            let parts: Vec<_> = jwt.split('.').collect();
            let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            public
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
                .unwrap();
            let header: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
            assert_eq!(header, json!({ "alg": "RS256", "typ": "JWT" }));
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(claims, json!({ "iat": 940, "exp": 1540, "iss": "123" }));
        }
        assert!(create_jwt("1", "garbage", 0).unwrap_err().contains("PEM"));
    }

    #[test]
    fn is_fresh_requires_more_than_min_ttl_minutes_of_validity() {
        let now = parse_time("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(now, 1_767_225_600_000);
        let c = |e: &str| Cached {
            token: Zeroizing::new("t".into()),
            expires_at: e.into(),
        };
        assert!(is_fresh(Some(&c("2026-01-01T00:10:00Z")), 5.0, now));
        assert!(!is_fresh(Some(&c("2026-01-01T00:04:00Z")), 5.0, now));
        assert!(!is_fresh(Some(&c("2026-01-01T00:29:00Z")), 30.0, now));
        assert!(is_fresh(Some(&c("2026-01-01T00:31:00Z")), 30.0, now));
        assert!(!is_fresh(Some(&c("garbage")), 0.0, now));
        assert!(!is_fresh(None, 5.0, now));
    }

    #[test]
    fn is_github_https_only_matches_https_github_com() {
        assert!(is_github_https(
            "protocol=https\nhost=github.com\npath=org/repo.git\n"
        ));
        assert!(!is_github_https("protocol=http\nhost=github.com\n"));
        assert!(!is_github_https(
            "protocol=https\nhost=github.com.evil.example\n"
        ));
        assert!(!is_github_https("protocol=https\nhost=gitlab.com\n"));
    }

    #[test]
    fn list_profiles_picks_gain_0_3_keychain_config_items_only() {
        let item = |svce: &str, acct: &str| {
            format!(
                "keychain: \"/x/login.keychain-db\"\nclass: \"genp\"\nattributes:\n    \"acct\"<blob>=\"{acct}\"\n    \"svce\"<blob>=\"{svce}\"\n"
            )
        };
        let dump = [
            item("gain", "token:work"),
            item("gain", "config:work"),
            item("gain", "config:default"),
            item("other", "config:nope"),
        ]
        .concat();
        assert_eq!(list_profiles(&dump), ["default", "work"]);
    }

    #[test]
    fn launchd_plist_escapes_paths() {
        let xml = launchd_plist(&args(&["/a&b/gain", "/x<y"]), "/l.log");
        assert!(xml.contains("<string>/a&amp;b/gain</string><string>/x&lt;y</string>"));
    }

    #[test]
    fn stable_copy_puts_an_executable_copy_next_to_the_vault() {
        let dir = tmp_vault().parent().unwrap().to_path_buf();
        let me = dir.join("node_modules/@mkusaka/gain/bin/gain");
        fs::create_dir_all(me.parent().unwrap()).unwrap();
        fs::write(&me, "binary v1").unwrap();
        fs::set_permissions(&me, fs::Permissions::from_mode(0o755)).unwrap();
        let data = dir.join("data");
        let copy = stable_copy(&me, &data).unwrap();
        assert_eq!(copy, data.join("bin/gain"));
        fs::write(&me, "binary v2").unwrap();
        stable_copy(&me, &data).unwrap(); // reinstall after an upgrade replaces it
        assert_eq!(fs::read_to_string(&copy).unwrap(), "binary v2");
        assert_eq!(
            fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&data).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn status_line_flags_an_agent_running_another_version() {
        let m = |v: Value| v.as_object().unwrap().clone();
        let line = status_line(&m(json!({ "unlocked": true, "version": "0.4.2" })), "0.4.2");
        assert_eq!(line, "unlocked (agent 0.4.2)");
        let line = status_line(
            &m(json!({ "unlocked": false, "version": "0.4.1" })),
            "0.4.2",
        );
        assert!(line.starts_with("locked ") && line.ends_with("gain agent install"));
        assert!(status_line(&m(json!({ "unlocked": false })), "0.4.2").contains("agent unknown"));
    }

    #[test]
    fn pick_installation_uses_the_only_installation_otherwise_asks() {
        let inst = |id, login: &str| Installation {
            id,
            account: Account {
                login: login.into(),
            },
        };
        assert_eq!(pick_installation(&[inst(42, "org")]).unwrap(), "42");
        assert!(
            pick_installation(&[])
                .unwrap_err()
                .contains("not installed")
        );
        let err = pick_installation(&[inst(1, "a"), inst(2, "b")]).unwrap_err();
        assert!(err.contains("1 (a), 2 (b)"));
    }

    #[test]
    fn check_hardened_requires_runtime_without_attach_or_injection_entitlements() {
        let signed = "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+7\n";
        assert!(check_hardened(signed));
        assert!(!check_hardened(
            "CodeDirectory flags=0x20002(adhoc,linker-signed) hashes=1"
        ));
        for e in [
            "get-task-allow",
            "allow-dyld-environment-variables",
            "disable-library-validation",
        ] {
            assert!(!check_hardened(&format!(
                "{signed}[Key] com.apple.security.{e}"
            )));
        }
    }

    #[test]
    fn parser_passes_non_gain_args_to_gh_untouched_and_bounds_min_ttl() {
        let run = |profile: &str, cmd| Cli::Run {
            profile: profile.into(),
            cmd,
        };
        let p = |a: &[&str]| parse(&args(a), None);
        assert_eq!(
            p(&["--profile", "w", "api", "x", "--jq", ".a", "--help"]).unwrap(),
            run("w", Cmd::Gh(args(&["api", "x", "--jq", ".a", "--help"])))
        );
        assert_eq!(p(&[]).unwrap(), run("default", Cmd::Gh(vec![])));
        assert_eq!(
            parse(&args(&["pr", "list", "--profile", "x"]), Some("env".into())).unwrap(),
            run("env", Cmd::Gh(args(&["pr", "list", "--profile", "x"])))
        );
        assert_eq!(
            p(&["token", "--min-ttl", "30"]).unwrap(),
            run("default", Cmd::Token { min_ttl: 30 })
        );
        assert_eq!(
            p(&["--profile=w", "token", "--min-ttl=0"]).unwrap(),
            run("w", Cmd::Token { min_ttl: 0 })
        );
        assert!(p(&["token", "--min-ttl", "61"]).is_err());
        assert!(p(&["token", "--min-ttl"]).is_err());
        assert_eq!(
            p(&["profile", "remove", "w"]).unwrap(),
            Cli::ProfileRemove("w".into())
        );
        assert_eq!(p(&["revoke"]).unwrap(), run("default", Cmd::Revoke));
        assert_eq!(
            p(&["agent", "unlock"]).unwrap(),
            Cli::Agent("unlock".into())
        );
        assert_eq!(p(&["agent", "reset"]).unwrap(), Cli::Agent("reset".into()));
        assert!(p(&["agent", "dump"]).is_err());
        assert_eq!(
            p(&["setup", "--private-key-path", "k.pem", "--client-id", "Iv1"]).unwrap(),
            run(
                "default",
                Cmd::Setup {
                    client_id: "Iv1".into(),
                    installation_id: None,
                    key_path: "k.pem".into()
                }
            )
        );
        assert!(p(&["setup", "--private-key-path", "k.pem"]).is_err());
        assert_eq!(
            p(&["credential", "get"]).unwrap(),
            run("default", Cmd::Credential("get".into()))
        );
    }
}

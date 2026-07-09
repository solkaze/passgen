use clap::Parser;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use termios::{tcsetattr, Termios, ECHO, ECHONL, ICANON, TCSAFLUSH};

// ============================================================
// ユーザー設定定数
// ============================================================

/// デフォルトのパスワード長
const DEFAULT_LENGTH: usize = 48;

/// デフォルトのPBKDF2イテレーション回数
const DEFAULT_ITERATIONS: u32 = 600_000;

/// パスワード長の最小値
const MIN_PASSWORD_LENGTH: usize = 8;

/// 導出キーの最小バイト数倍率
const KEY_LENGTH_MULTIPLIER: usize = 8;

/// 導出キーの最低保証バイト数
const KEY_LENGTH_MIN: usize = 64;

/// saltのサフィックス
const SALT_SUFFIX: &str = ":passgen";

/// コアパスワード入力プロンプト
const PROMPT_CORE_PASSWORD: &str = "コアパスワードを入力してください: ";

/// シードファイル名
const SEED_FILE_NAME: &str = ".pass-gen-seed";

/// シードファイルのパーミッション（Unix のみ）
#[cfg(unix)]
const SEED_FILE_MODE: u32 = 0o600;

/// シードのバイト長
const SEED_BYTES: usize = 32;

/// サーバーのデフォルトポート
const DEFAULT_SERVER_PORT: u16 = 11010;

/// .env ファイル名（プロジェクトルートに配置）
const ENV_FILE_NAME: &str = ".env";

/// HTML ディレクトリ名（プロジェクトルート配下）
const HTML_DIR_NAME: &str = "html";

/// HTML ファイル名
const HTML_FILE_NAME: &str = "index.html";

// ============================================================
// 文字セット定数
// ============================================================

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

const ENSURE_DIGITS_POS_OFFSET: usize = 2;
const ENSURE_DIGITS_CHAR_OFFSET: usize = 3;
const ENSURE_SYMBOLS_POS_OFFSET: usize = 3;
const ENSURE_SYMBOLS_CHAR_OFFSET: usize = 4;

// ============================================================
// CLIの定義
// ============================================================

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// サイト名
    #[arg(short, long, default_value = "")]
    site: String,

    /// 生成するパスワードの長さ
    #[arg(short, long, default_value_t = DEFAULT_LENGTH)]
    length: usize,

    /// PBKDF2のイテレーション回数
    #[arg(short, long, default_value_t = DEFAULT_ITERATIONS)]
    iterations: u32,

    /// 生成したパスワードをクリップボードにコピーする
    #[arg(short, long)]
    copy: bool,

    /// ブラウザUIモードで起動する
    #[arg(short = 'S', long = "server")]
    server: bool,

    /// 数字を含めない
    #[arg(long = "no-digits")]
    no_digits: bool,

    /// 記号を含めない
    #[arg(long = "no-symbols")]
    no_symbols: bool,

    /// 使用可能な記号を指定する
    #[arg(short = 'C', long = "char")]
    custom_symbols: Option<String>,
}

// ============================================================
// 設定ディレクトリ・ファイルパス
// ============================================================

fn home_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("ホームディレクトリが取得できません");
    PathBuf::from(home)
}

/// 実行ファイルから見たプロジェクトルートを返す。
/// 実行ファイルは `<project>/target/release/pass-gen` に置かれている想定で、
/// 2 階層上をプロジェクトルートとする。
/// `init.sh` で `/usr/local/bin/pass-gen` にシンボリックリンクを張った場合でも、
/// `current_exe()` はリンクの実体パスを返すので同じ解決ができる。
fn project_root() -> PathBuf {
    let exe = std::env::current_exe()
        .expect("実行ファイルのパスを取得できません");
    exe.parent()       // target/release
        .and_then(|p| p.parent())   // target
        .and_then(|p| p.parent())   // project root
        .expect("プロジェクトルートの解決に失敗しました")
        .to_path_buf()
}

fn env_file_path() -> PathBuf {
    project_root().join(ENV_FILE_NAME)
}

fn html_file_path() -> PathBuf {
    project_root().join(HTML_DIR_NAME).join(HTML_FILE_NAME)
}

fn seed_file_path() -> PathBuf {
    home_dir().join(SEED_FILE_NAME)
}

// ============================================================
// .env 処理
// ============================================================

/// .env を読み込んでポート番号を返す。なければデフォルト値で .env を自動生成する。
fn load_or_create_env() -> u16 {
    let env_path = env_file_path();

    if !env_path.exists() {
        eprintln!(".env が見つかりません。デフォルト値で生成します: {}", env_path.display());
        let content = format!(
            "# pass-gen 設定ファイル\n\
             # サーバーのポート番号\n\
             PORT={}\n",
            DEFAULT_SERVER_PORT
        );
        fs::write(&env_path, content).expect(".env の書き込みに失敗しました");
        eprintln!(".env を生成しました: {}", env_path.display());
    }

    // .env を読み込む
    dotenvy::from_path(&env_path).ok();
    std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SERVER_PORT)
}

// ============================================================
// HTML ファイル処理
// ============================================================

/// HTMLファイルを読み込む。存在しない場合はエラーで終了する。
fn load_html() -> String {
    let html_path = html_file_path();
    if !html_path.exists() {
        eprintln!("エラー: index.html が見つかりません: {}", html_path.display());
        eprintln!("プロジェクトの html/index.html が存在するか確認してください。");
        std::process::exit(1);
    }
    fs::read_to_string(&html_path).expect("index.html の読み込みに失敗しました")
}


// ============================================================
// コアパスワード入力
// ============================================================

#[cfg(unix)]
fn prompt_masked(prompt: &str) -> String {
    let stdin_fd = 0;
    let mut termios = Termios::from_fd(stdin_fd).expect("termios の取得に失敗しました");
    let original = termios;
    termios.c_lflag &= !(ECHO | ECHONL | ICANON);
    tcsetattr(stdin_fd, TCSAFLUSH, &termios).expect("termios の設定に失敗しました");

    let tty_fd = unsafe {
        libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR)
    };
    if tty_fd < 0 {
        eprintln!("エラー: /dev/tty を開けませんでした");
        std::process::exit(1);
    }
    let mut tty = unsafe { fs::File::from_raw_fd(tty_fd) };

    write!(tty, "{}", prompt).unwrap();
    tty.flush().unwrap();

    let mut password = String::new();
    let mut buf = [0u8; 1];
    loop {
        tty.read_exact(&mut buf).expect("入力の読み込みに失敗しました");
        match buf[0] {
            b'\n' | b'\r' => {
                writeln!(tty).unwrap();
                tty.flush().unwrap();
                break;
            }
            127 | 8 => {
                if !password.is_empty() {
                    password.pop();
                    write!(tty, "\x08 \x08").unwrap();
                    tty.flush().unwrap();
                }
            }
            c if c >= 0x20 => {
                password.push(c as char);
                write!(tty, "*").unwrap();
                tty.flush().unwrap();
            }
            _ => {}
        }
    }
    tcsetattr(stdin_fd, TCSAFLUSH, &original).expect("termios の復元に失敗しました");
    password
}

#[cfg(windows)]
fn prompt_masked(prompt: &str) -> String {
    rpassword::prompt_password(prompt).expect("入力エラー")
}

// ============================================================
// クリップボード処理
// ============================================================

#[cfg(unix)]
fn copy_to_clipboard(password: &str) {
    use std::process::{Command, Stdio};
    let commands: &[(&str, &[&str])] = &[
        ("clip.exe", &[]),
        ("wl-copy",  &[]),
        ("xclip",    &["-selection", "clipboard"]),
        ("xsel",     &["--clipboard", "--input"]),
    ];
    for (cmd, args) in commands {
        let result = Command::new(cmd).args(*args).stdin(Stdio::piped()).spawn();
        if let Ok(mut child) = result {
            if let Some(stdin) = child.stdin.take() {
                let mut stdin = stdin;
                let _ = stdin.write_all(password.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                eprintln!("クリップボードにコピーしました。({} を使用)", cmd);
                return;
            }
        }
    }
    eprintln!("クリップボードへのコピーに失敗しました。clip.exe / wl-copy / xclip / xsel のいずれかが必要です。");
}

#[cfg(windows)]
fn copy_to_clipboard(password: &str) {
    use arboard::Clipboard;
    match Clipboard::new().and_then(|mut cb| cb.set_text(password)) {
        Ok(_) => eprintln!("クリップボードにコピーしました。"),
        Err(e) => eprintln!("クリップボードへのコピーに失敗しました: {}", e),
    }
}

// ============================================================
// シードファイル処理
// ============================================================

fn load_or_create_seed(path: &PathBuf) -> Vec<u8> {
    if path.exists() {
        let seed = fs::read(path).expect("シードファイルの読み込みに失敗しました");
        if seed.is_empty() {
            eprintln!("エラー: シードファイルが空です: {}", path.display());
            std::process::exit(1);
        }
        seed
    } else {
        eprintln!("シードファイルが見つかりません。新規生成します: {}", path.display());
        let seed = generate_seed();
        save_seed(path, &seed);
        eprintln!("シードファイルを生成しました: {}", path.display());
        eprintln!("別端末で使用する場合はこのファイルをコピーしてください。");
        seed
    }
}

fn generate_seed() -> Vec<u8> {
    let mut buf = vec![0u8; SEED_BYTES];
    getrandom::getrandom(&mut buf).expect("乱数生成に失敗しました");
    buf
}

#[cfg(unix)]
fn save_seed(path: &PathBuf, seed: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .mode(SEED_FILE_MODE)
        .open(path)
        .expect("シードファイルの作成に失敗しました");
    file.write_all(seed).expect("シードファイルへの書き込みに失敗しました");
    eprintln!("パーミッション: {:04o}", SEED_FILE_MODE);
}

#[cfg(windows)]
fn save_seed(path: &PathBuf, seed: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(path)
        .expect("シードファイルの作成に失敗しました");
    file.write_all(seed).expect("シードファイルへの書き込みに失敗しました");
}

// ============================================================
// コア処理
// ============================================================

fn build_core(core: &str, seed: &[u8]) -> String {
    let seed_hex: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}:{}", seed_hex, core)
}

fn derive_key(core: &str, salt: &str, iterations: u32, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    pbkdf2::<Hmac<Sha256>>(core.as_bytes(), salt.as_bytes(), iterations, &mut key)
        .expect("PBKDF2 failed");
    key
}

/// key_bytes をパスワード文字列に変換する。
/// `symbols` には記号として使用する文字集合を渡す（use_symbols が true の場合のみ使用される）。
/// デフォルトの記号セットを使う場合は SYMBOLS 定数を渡し、
/// サイト固有の制限がある場合は呼び出し側で用意したカスタム記号セットを渡す。
fn bytes_to_password(key_bytes: &[u8], length: usize, use_digits: bool, use_symbols: bool, symbols: &[u8]) -> String {
    let all_chars: Vec<u8> = [
        Some(UPPERCASE),
        Some(LOWERCASE),
        if use_digits  { Some(DIGITS)  } else { None },
        if use_symbols { Some(symbols) } else { None },
    ]
    .iter()
    .flatten()
    .flat_map(|s| s.iter().copied())
    .collect();
    let total = all_chars.len();

    let mut raw: Vec<u8> = key_bytes.chunks(8)
        .flat_map(|chunk| {
            let mut buf = [0u8; 8];
            let len = chunk.len().min(8);
            buf[..len].copy_from_slice(&chunk[..len]);
            let n = u64::from_be_bytes(buf);
            std::iter::once(all_chars[(n as usize) % total])
        })
        .take(length)
        .collect();

    while raw.len() < length {
        let idx = raw.len();
        let n = key_bytes[idx % key_bytes.len()] as usize;
        raw.push(all_chars[n % total]);
    }

    // 有効な場合のみ必須文字を保証する
    let mut ensure_sets: Vec<(&[u8], usize, usize)> = Vec::new();
    if use_digits  { ensure_sets.push((DIGITS,  ENSURE_DIGITS_POS_OFFSET,  ENSURE_DIGITS_CHAR_OFFSET)); }
    if use_symbols { ensure_sets.push((symbols, ENSURE_SYMBOLS_POS_OFFSET, ENSURE_SYMBOLS_CHAR_OFFSET)); }

    for (charset, pos_offset, char_offset) in &ensure_sets {
        let already_present = raw.iter().any(|c| charset.contains(c));
        if !already_present {
            let pos = key_bytes[pos_offset  % key_bytes.len()] as usize % length;
            let ch  = key_bytes[char_offset % key_bytes.len()] as usize % charset.len();
            raw[pos] = charset[ch];
        }
    }
    String::from_utf8(raw).expect("Invalid UTF-8 in password")
}

/// パスワード生成の各種オプションをまとめた構造体。
/// generate_password の引数がclippyのtoo_many_arguments閾値を超えないよう、
/// core/site/seed（対象の識別情報）以外の生成条件をここに集約する。
struct GenerateOptions<'a> {
    length: usize,
    iterations: u32,
    use_digits: bool,
    use_symbols: bool,
    symbols: &'a [u8],
}

fn generate_password(core: &str, site: &str, seed: &[u8], opts: &GenerateOptions) -> String {
    let combined_core = build_core(core, seed);
    let salt = format!("{}{}", site, SALT_SUFFIX);
    let key_len = (opts.length * KEY_LENGTH_MULTIPLIER).max(KEY_LENGTH_MIN);
    let key = derive_key(&combined_core, &salt, opts.iterations, key_len);
    bytes_to_password(&key, opts.length, opts.use_digits, opts.use_symbols, opts.symbols)
}

// ============================================================
// サーバーモード
// ============================================================

/// WSL2かどうかを検出してブラウザを起動する
fn open_browser(url: &str) {
    let is_wsl = std::fs::read_to_string("/proc/version")
        .map(|v| v.to_lowercase().contains("microsoft"))
        .unwrap_or(false);

    if is_wsl {
        // WSL2ではcmd.exe経由でWindowsのブラウザを起動
        match std::process::Command::new("cmd.exe")
            .args(["/c", "start", url])
            .spawn()
        {
            Ok(_) => {}
            Err(e) => eprintln!("ブラウザの起動に失敗しました: {} — 手動でアクセスしてください: {}", e, url),
        }
    } else {
        if let Err(e) = open::that(url) {
            eprintln!("ブラウザの起動に失敗しました: {} — 手動でアクセスしてください: {}", e, url);
        }
    }
}

fn run_server(port: u16, seed: Vec<u8>, html: String) {
    let addr = format!("127.0.0.1:{}", port);
    let server = tiny_http::Server::http(&addr)
        .expect("サーバーの起動に失敗しました");

    let url = format!("http://localhost:{}", port);
    eprintln!("サーバーを起動しました: {}", url);
    eprintln!("終了するには Ctrl+C またはブラウザの終了ボタンを押してください");

    open_browser(&url);

    for request in server.incoming_requests() {
        let method = request.method().clone();
        let url_path = request.url().to_string();

        match (method, url_path.as_str()) {
            (tiny_http::Method::Get, "/") => {
                let response = tiny_http::Response::from_string(html.clone())
                    .with_header("Content-Type: text/html; charset=utf-8".parse::<tiny_http::Header>().unwrap());
                let _ = request.respond(response);
            }

            (tiny_http::Method::Post, "/generate") => {
                let mut body = String::new();
                let mut req = request;
                let _ = req.as_reader().read_to_string(&mut body);
                let json_response = parse_and_generate(&body, &seed);
                let response = tiny_http::Response::from_string(json_response)
                    .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap())
                    .with_header("Access-Control-Allow-Origin: *".parse::<tiny_http::Header>().unwrap());
                let _ = req.respond(response);
            }

            // 終了ボタン・ウィンドウを閉じた際のシャットダウン
            (tiny_http::Method::Post, "/shutdown") => {
                let response = tiny_http::Response::from_string(r#"{"status":"bye"}"#)
                    .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap())
                    .with_header("Access-Control-Allow-Origin: *".parse::<tiny_http::Header>().unwrap());
                let _ = request.respond(response);
                eprintln!("シャットダウン要求を受信しました。終了します。");
                std::process::exit(0);
            }

            (tiny_http::Method::Options, _) => {
                let response = tiny_http::Response::empty(200)
                    .with_header("Access-Control-Allow-Origin: *".parse::<tiny_http::Header>().unwrap())
                    .with_header("Access-Control-Allow-Methods: POST, GET, OPTIONS".parse::<tiny_http::Header>().unwrap())
                    .with_header("Access-Control-Allow-Headers: Content-Type".parse::<tiny_http::Header>().unwrap());
                let _ = request.respond(response);
            }

            _ => { let _ = request.respond(tiny_http::Response::empty(404)); }
        }
    }
}

fn parse_and_generate(body: &str, seed: &[u8]) -> String {
    let site        = extract_json_str(body, "site").unwrap_or_default();
    let core        = extract_json_str(body, "master").unwrap_or_default();
    let length      = extract_json_num(body, "length").unwrap_or(DEFAULT_LENGTH as u64) as usize;
    let iterations  = extract_json_num(body, "iterations").unwrap_or(DEFAULT_ITERATIONS as u64) as u32;
    let use_digits  = extract_json_bool(body, "use_digits").unwrap_or(true);
    let use_symbols = extract_json_bool(body, "use_symbols").unwrap_or(true);

    if core.is_empty() {
        return r#"{"error":"コアパスワードが空です"}"#.to_string();
    }
    if length < MIN_PASSWORD_LENGTH {
        return format!(r#"{{"error":"パスワード長は{}文字以上にしてください"}}"#, MIN_PASSWORD_LENGTH);
    }

    // GUI側でのカスタム記号セット対応は今後実装予定。現時点ではデフォルトの記号セットを使用する。
    let opts = GenerateOptions {
        length,
        iterations,
        use_digits,
        use_symbols,
        symbols: SYMBOLS,
    };
    let password = generate_password(&core, &site, seed, &opts);
    format!(r#"{{"password":"{}"}}"#, password)
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}""#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!(r#""{}""#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    if rest.starts_with("true")  { return Some(true);  }
    if rest.starts_with("false") { return Some(false); }
    None
}

fn extract_json_num(json: &str, key: &str) -> Option<u64> {
    let pattern = format!(r#""{}""#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ============================================================
// main
// ============================================================

fn main() {
    let args = Args::parse();

    let seed_path = seed_file_path();
    let seed = load_or_create_seed(&seed_path);

    if args.server {
        let port = load_or_create_env();
        let html = load_html();
        run_server(port, seed, html);
        return;
    }

    // CLIモード
    if args.length < MIN_PASSWORD_LENGTH {
        eprintln!("エラー: パスワード長は{}文字以上を指定してください。", MIN_PASSWORD_LENGTH);
        std::process::exit(1);
    }

    let core = prompt_masked(PROMPT_CORE_PASSWORD);
    if core.is_empty() {
        eprintln!("エラー: コアパスワードが空です。");
        std::process::exit(1);
    }

    let use_digits  = !args.no_digits;
    let mut use_symbols = !args.no_symbols;

    // -C/--char が指定された場合、デフォルトの記号セットを置き換える
    let symbols: Vec<u8> = match &args.custom_symbols {
        Some(custom) => {
            if custom.is_empty() {
                eprintln!("エラー: -C/--char には1文字以上指定してください。");
                std::process::exit(1);
            }
            if !custom.is_ascii() {
                eprintln!("エラー: -C/--char はASCII文字のみ指定できます。");
                std::process::exit(1);
            }
            if args.no_symbols {
                eprintln!("警告: --no-symbols が指定されていますが、-C/--char が指定されたため記号を使用します。");
            }
            use_symbols = true;

            // 重複文字を除去する（入力順は保持）。重複があっても動作上問題はないが、
            // 同じ文字が複数枠を占めることによる分布の偏りを避けるため除去する。
            let mut seen = std::collections::HashSet::new();
            custom.bytes().filter(|b| seen.insert(*b)).collect()
        }
        None => SYMBOLS.to_vec(),
    };

    eprintln!(
        "生成中... (site={:?}, length={}, iterations={}, digits={}, symbols={})",
        if args.site.is_empty() { "(なし)" } else { &args.site },
        args.length,
        args.iterations,
        use_digits,
        use_symbols,
    );

    let opts = GenerateOptions {
        length: args.length,
        iterations: args.iterations,
        use_digits,
        use_symbols,
        symbols: &symbols,
    };
    let password = generate_password(&core, &args.site, &seed, &opts);
    let border = "-".repeat(password.len());
    eprintln!("{}", border);
    println!("{}", password);
    eprintln!("{}", border);

    if args.copy {
        copy_to_clipboard(&password);
    }
}

// ============================================================
// テスト
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_direct(core: &str, site: &str, iterations: u32, seed: &[u8]) -> Vec<u8> {
        let key_len = (DEFAULT_LENGTH * KEY_LENGTH_MULTIPLIER).max(KEY_LENGTH_MIN);
        let combined = build_core(core, seed);
        let salt = format!("{}{}", site, SALT_SUFFIX);
        derive_key(&combined, &salt, iterations, key_len)
    }

    #[test]
    fn test_deterministic() {
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("mysecret", "example.com", DEFAULT_ITERATIONS, &seed);
        assert_eq!(bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS), bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS));
    }

    #[test]
    fn test_default_length() {
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("mysecret", "example.com", DEFAULT_ITERATIONS, &seed);
        assert_eq!(bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS).chars().count(), DEFAULT_LENGTH);
    }

    #[test]
    fn test_different_sites() {
        let seed = vec![0u8; SEED_BYTES];
        let key1 = test_key_direct("mysecret", "siteA", DEFAULT_ITERATIONS, &seed);
        let key2 = test_key_direct("mysecret", "siteB", DEFAULT_ITERATIONS, &seed);
        assert_ne!(bytes_to_password(&key1, DEFAULT_LENGTH, true, true, SYMBOLS), bytes_to_password(&key2, DEFAULT_LENGTH, true, true, SYMBOLS));
    }

    #[test]
    fn test_contains_digit_and_symbol() {
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("testmaster", "testsite", 10_000, &seed);
        let p = bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS);
        assert!(p.chars().any(|c| c.is_ascii_digit()), "数字が含まれていない");
        assert!(p.chars().any(|c| SYMBOLS.contains(&(c as u8))), "記号が含まれていない");
    }

    #[test]
    fn test_custom_length() {
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("mysecret", "", 10_000, &seed);
        for len in [MIN_PASSWORD_LENGTH, 16, 24, 64] {
            let p = bytes_to_password(&key, len, true, true, SYMBOLS);
            assert_eq!(p.chars().count(), len, "長さ{}のテスト失敗", len);
        }
    }

    #[test]
    fn test_build_core_deterministic() {
        let seed = vec![0u8; SEED_BYTES];
        assert_eq!(build_core("mykey", &seed), build_core("mykey", &seed));
    }

    #[test]
    fn test_different_seeds() {
        let seed1 = vec![0u8; SEED_BYTES];
        let seed2 = vec![1u8; SEED_BYTES];
        let key1 = test_key_direct("mykey", "example.com", 10_000, &seed1);
        let key2 = test_key_direct("mykey", "example.com", 10_000, &seed2);
        assert_ne!(bytes_to_password(&key1, DEFAULT_LENGTH, true, true, SYMBOLS), bytes_to_password(&key2, DEFAULT_LENGTH, true, true, SYMBOLS));
    }

    #[test]
    fn test_parse_and_generate() {
        let seed = vec![0u8; SEED_BYTES];
        let body = r#"{"site":"example.com","master":"testkey","length":48,"iterations":10000}"#;
        let result = parse_and_generate(body, &seed);
        assert!(result.contains("password"));
    }

    #[test]
    fn test_custom_symbols_restricts_charset() {
        // カスタム記号セットを指定した場合、デフォルトの記号セット由来の文字が
        // 混入しないことを確認する
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("mysecret", "example.com", 10_000, &seed);
        let custom: &[u8] = b"!\"#$%";
        let p = bytes_to_password(&key, DEFAULT_LENGTH, true, true, custom);
        for c in p.bytes() {
            let allowed = UPPERCASE.contains(&c) || LOWERCASE.contains(&c) || DIGITS.contains(&c) || custom.contains(&c);
            assert!(allowed, "許可されていない文字が含まれている: {}", c as char);
        }
    }

    #[test]
    fn test_custom_symbols_single_char_boundary() {
        // 記号が1文字しかない極端なケースでも必須文字保証ロジックが破綻しないこと
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("mysecret", "example.com", 10_000, &seed);
        let tiny: &[u8] = b"$";
        let p = bytes_to_password(&key, 12, true, true, tiny);
        assert!(p.bytes().any(|c| c == b'$'));
    }
}

use clap::ValueEnum;

use crate::config::{
    DEFAULT_ARGON2_MEMORY_COST_KIB, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ITERATIONS, DEFAULT_LENGTH, MIN_PASSWORD_LENGTH,
};
use crate::kdf::{generate_password, GenerateOptions, KdfAlgorithm, SYMBOLS};

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
            Err(e) => eprintln!(
                "ブラウザの起動に失敗しました: {} — 手動でアクセスしてください: {}",
                e, url
            ),
        }
    } else if let Err(e) = open::that(url) {
        eprintln!(
            "ブラウザの起動に失敗しました: {} — 手動でアクセスしてください: {}",
            e, url
        );
    }
}

pub fn run_server(port: u16, seed: Vec<u8>, html: String) {
    let addr = format!("127.0.0.1:{}", port);
    let server = tiny_http::Server::http(&addr).expect("サーバーの起動に失敗しました");

    let url = format!("http://localhost:{}", port);
    eprintln!("サーバーを起動しました: {}", url);
    eprintln!("終了するには Ctrl+C またはブラウザの終了ボタンを押してください");

    open_browser(&url);

    for request in server.incoming_requests() {
        let method = request.method().clone();
        let url_path = request.url().to_string();

        match (method, url_path.as_str()) {
            (tiny_http::Method::Get, "/") => {
                let response = tiny_http::Response::from_string(html.clone()).with_header(
                    "Content-Type: text/html; charset=utf-8"
                        .parse::<tiny_http::Header>()
                        .unwrap(),
                );
                let _ = request.respond(response);
            }

            (tiny_http::Method::Post, "/generate") => {
                let mut body = String::new();
                let mut req = request;
                let _ = req.as_reader().read_to_string(&mut body);
                let json_response = parse_and_generate(&body, &seed);
                let response = tiny_http::Response::from_string(json_response)
                    .with_header(
                        "Content-Type: application/json"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    )
                    .with_header(
                        "Access-Control-Allow-Origin: *"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                let _ = req.respond(response);
            }

            // 終了ボタン・ウィンドウを閉じた際のシャットダウン
            (tiny_http::Method::Post, "/shutdown") => {
                let response = tiny_http::Response::from_string(r#"{"status":"bye"}"#)
                    .with_header(
                        "Content-Type: application/json"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    )
                    .with_header(
                        "Access-Control-Allow-Origin: *"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                let _ = request.respond(response);
                eprintln!("シャットダウン要求を受信しました。終了します。");
                std::process::exit(0);
            }

            (tiny_http::Method::Options, _) => {
                let response = tiny_http::Response::empty(200)
                    .with_header(
                        "Access-Control-Allow-Origin: *"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    )
                    .with_header(
                        "Access-Control-Allow-Methods: POST, GET, OPTIONS"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    )
                    .with_header(
                        "Access-Control-Allow-Headers: Content-Type"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                let _ = request.respond(response);
            }

            _ => {
                let _ = request.respond(tiny_http::Response::empty(404));
            }
        }
    }
}

fn parse_and_generate(body: &str, seed: &[u8]) -> String {
    let site = extract_json_str(body, "site").unwrap_or_default();
    let core = extract_json_str(body, "master").unwrap_or_default();
    let length = extract_json_num(body, "length").unwrap_or(DEFAULT_LENGTH as u64) as usize;
    let kdf_str = extract_json_str(body, "kdf").unwrap_or_else(|| "argon2id".to_string());
    let kdf = KdfAlgorithm::from_str(&kdf_str, true).unwrap_or(KdfAlgorithm::Argon2id);
    let pbkdf2_iterations =
        extract_json_num(body, "iterations").unwrap_or(DEFAULT_ITERATIONS as u64) as u32;
    let argon2_time_cost =
        extract_json_num(body, "time_cost").unwrap_or(DEFAULT_ARGON2_TIME_COST as u64) as u32;
    let argon2_memory_cost = extract_json_num(body, "memory_cost")
        .unwrap_or(DEFAULT_ARGON2_MEMORY_COST_KIB as u64) as u32;
    let argon2_parallelism =
        extract_json_num(body, "parallelism").unwrap_or(DEFAULT_ARGON2_PARALLELISM as u64) as u32;
    let use_digits = extract_json_bool(body, "use_digits").unwrap_or(true);
    let use_symbols = extract_json_bool(body, "use_symbols").unwrap_or(true);

    if core.is_empty() {
        return r#"{"error":"コアパスワードが空です"}"#.to_string();
    }
    if length < MIN_PASSWORD_LENGTH {
        return format!(
            r#"{{"error":"パスワード長は{}文字以上にしてください"}}"#,
            MIN_PASSWORD_LENGTH
        );
    }

    // GUI側でのカスタム記号セット対応は今後実装予定。現時点ではデフォルトの記号セットを使用する。
    let opts = GenerateOptions {
        length,
        kdf,
        pbkdf2_iterations,
        argon2_time_cost,
        argon2_memory_cost,
        argon2_parallelism,
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
    if rest.starts_with("true") {
        return Some(true);
    }
    if rest.starts_with("false") {
        return Some(false);
    }
    None
}

fn extract_json_num(json: &str, key: &str) -> Option<u64> {
    let pattern = format!(r#""{}""#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ============================================================
// テスト
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_generate_argon2id_default() {
        let seed = vec![0u8; crate::config::SEED_BYTES];
        let body = r#"{"site":"example.com","master":"testkey","length":48,"time_cost":1,"memory_cost":8192,"parallelism":1}"#;
        let result = parse_and_generate(body, &seed);
        assert!(result.contains("password"));
    }

    #[test]
    fn test_parse_and_generate_pbkdf2_explicit() {
        let seed = vec![0u8; crate::config::SEED_BYTES];
        let body = r#"{"site":"example.com","master":"testkey","length":48,"kdf":"pbkdf2","iterations":10000}"#;
        let result = parse_and_generate(body, &seed);
        assert!(result.contains("password"));
    }
}

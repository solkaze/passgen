use std::fs;
use std::io::Write;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::config::SEED_BYTES;

#[cfg(unix)]
use crate::config::SEED_FILE_MODE;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// ============================================================
// シードファイル処理
// ============================================================

pub fn load_or_create_seed(path: &PathBuf) -> Vec<u8> {
    if !path.exists() {
        migrate_legacy_seed(path);
    }

    if path.exists() {
        #[cfg(unix)]
        check_seed_permissions(path);

        let raw = fs::read(path).expect("シードファイルの読み込みに失敗しました");
        if raw.is_empty() {
            eprintln!("エラー: シードファイルが空です: {}", path.display());
            std::process::exit(1);
        }
        decode_seed(&raw)
    } else {
        eprintln!(
            "シードファイルが見つかりません。新規生成します: {}",
            path.display()
        );
        let seed = generate_seed();
        save_seed(path, &seed);
        eprintln!("シードファイルを生成しました: {}", path.display());
        eprintln!("別端末で使用する場合はこのファイルをコピーしてください。");
        seed
    }
}

/// 旧パス（~/.pass-gen-seed）にシードファイルが残っている場合、新パスへ移行する。
/// 既存パスワードとの互換性を保つため、新規生成より移行を優先する。
fn migrate_legacy_seed(path: &PathBuf) {
    let legacy_path = crate::config::legacy_seed_file_path();
    if !legacy_path.exists() {
        return;
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("設定ディレクトリの作成に失敗しました");
    }
    fs::rename(&legacy_path, path).expect("シードファイルの移行に失敗しました");
    eprintln!(
        "シードファイルを移行しました: {} -> {}",
        legacy_path.display(),
        path.display()
    );
}

/// シードファイルの中身を読み込み用のバイト列にデコードする。
/// 新形式（SSH秘密鍵のようなbase64テキスト）を優先して解釈し、
/// 旧バージョンで生成された生バイナリ形式のファイルとも互換性を保つ。
fn decode_seed(raw: &[u8]) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if let Ok(decoded) = BASE64.decode(trimmed) {
            if !decoded.is_empty() {
                return decoded;
            }
        }
    }
    // 旧形式（生バイナリ）として扱う
    raw.to_vec()
}

fn generate_seed() -> Vec<u8> {
    let mut buf = vec![0u8; SEED_BYTES];
    getrandom::getrandom(&mut buf).expect("乱数生成に失敗しました");
    buf
}

/// シードをbase64エンコードし、SSH秘密鍵のようなランダムな文字列として保存する。
fn encode_seed(seed: &[u8]) -> String {
    let mut encoded = BASE64.encode(seed);
    encoded.push('\n');
    encoded
}

#[cfg(unix)]
fn save_seed(path: &PathBuf, seed: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("設定ディレクトリの作成に失敗しました");
    }
    let text = encode_seed(seed);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(SEED_FILE_MODE)
        .open(path)
        .expect("シードファイルの作成に失敗しました");
    file.write_all(text.as_bytes())
        .expect("シードファイルへの書き込みに失敗しました");
    eprintln!("パーミッション: {:04o}", SEED_FILE_MODE);
}

#[cfg(windows)]
fn save_seed(path: &PathBuf, seed: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("設定ディレクトリの作成に失敗しました");
    }
    let text = encode_seed(seed);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("シードファイルの作成に失敗しました");
    file.write_all(text.as_bytes())
        .expect("シードファイルへの書き込みに失敗しました");
}

/// シードファイルのパーミッションを検査する。
/// SSH秘密鍵と同様、所有者以外からの読み取りが可能な状態は情報漏洩のリスクがあるため、
/// 600（所有者のみ読み書き可能）でない場合は実行を中止する。
#[cfg(unix)]
fn check_seed_permissions(path: &PathBuf) {
    let metadata = fs::metadata(path).expect("シードファイルの情報取得に失敗しました");
    let mode = metadata.permissions().mode() & 0o777;
    if mode != SEED_FILE_MODE {
        eprintln!(
            "エラー: シードファイルのパーミッションが不正です: {} (現在: {:04o}, 期待値: {:04o})",
            path.display(),
            mode,
            SEED_FILE_MODE
        );
        eprintln!("秘密鍵と同様に扱う必要があるため、他ユーザーから読み取れない状態にしてください:");
        eprintln!("  chmod {:o} {}", SEED_FILE_MODE, path.display());
        std::process::exit(1);
    }
}

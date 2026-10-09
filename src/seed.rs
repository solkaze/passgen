use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::config::SEED_BYTES;

#[cfg(unix)]
use crate::config::{DATA_DIR_MODE, SEED_FILE_MODE};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

// ============================================================
// シードファイル処理
// ============================================================

/// PEM風の開始行。SSHやTLSの秘密鍵ファイルと同様の見た目にすることで、
/// 「これは秘密鍵として扱うべきファイルである」ことを一目で示す。
const PEM_BEGIN: &str = "-----BEGIN PASSGEN PRIVATE SEED-----";
/// PEM風の終了行。
const PEM_END: &str = "-----END PASSGEN PRIVATE SEED-----";
/// ファイル内に埋め込む警告コメント行。
const PEM_WARNING: &str =
    "Comment: これは秘密鍵に相当します。内容を表示・共有・コミットしないでください。";
/// PEM形式でのbase64の折り返し幅（RFC 7468のPEM表記に準拠）。
const PEM_LINE_WIDTH: usize = 64;

pub fn load_or_create_seed(path: &PathBuf) -> Vec<u8> {
    if !path.exists() {
        migrate_legacy_seed(path, &crate::config::legacy_seed_file_paths());
    }

    if path.exists() {
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
        eprintln!(
            "これはSSH秘密鍵などと同様、他人に見せたり共有したりしてはいけないファイルです。"
        );
        eprintln!("別端末で使用する場合はこのファイルをコピーしてください。");
        seed
    }
}

/// 旧パス（~/.config/passgen/passgen_seed、~/.pass-gen-seed）にシードファイルが
/// 残っている場合、新パスへ移行する。
/// 既存パスワードとの互換性を保つため、新規生成より移行を優先する。
fn migrate_legacy_seed(path: &Path, legacy_paths: &[PathBuf]) {
    let Some(legacy_path) = legacy_paths.iter().find(|p| p.exists()) else {
        return;
    };

    if let Some(parent) = path.parent() {
        create_data_dir(parent);
    }
    move_file(legacy_path, path).expect("シードファイルの移行に失敗しました");
    eprintln!(
        "シードファイルを移行しました: {} -> {}",
        legacy_path.display(),
        path.display()
    );
}

/// ファイルを移動する。renameはファイルシステムをまたげないため、失敗時はコピーで代替する。
/// コピーが途中で失敗しても壊れたシードが移行先に残らないよう、
/// 一時ファイルへコピーしてからrenameで確定させる。
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let tmp = to.with_extension("tmp");
    fs::copy(from, &tmp)?;
    fs::rename(&tmp, to)?;
    fs::remove_file(from)
}

/// シードファイルを置くデータディレクトリを作成する。
/// Unix では新規作成時のみ 0700 とし、既存ディレクトリのパーミッションは変更しない。
#[cfg(unix)]
fn create_data_dir(dir: &Path) {
    if dir.is_dir() {
        return;
    }
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).expect("データディレクトリの作成に失敗しました");
    }
    fs::DirBuilder::new()
        .mode(DATA_DIR_MODE)
        .create(dir)
        .expect("データディレクトリの作成に失敗しました");
}

#[cfg(windows)]
fn create_data_dir(dir: &Path) {
    fs::create_dir_all(dir).expect("データディレクトリの作成に失敗しました");
}

/// シードファイルの中身を読み込み用のバイト列にデコードする。
/// 現行形式（PEM風にBEGIN/ENDで囲んだbase64テキスト）を最優先で解釈し、
/// 旧形式（BEGIN/ENDなしの1行base64テキスト）、
/// さらに旧バージョンで生成された生バイナリ形式のファイルとも互換性を保つ。
fn decode_seed(raw: &[u8]) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(raw) {
        if let Some(decoded) = decode_pem_seed(text) {
            return decoded;
        }
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

/// PEM風形式（BEGIN/ENDマーカーと折り返しbase64、コメント行）からシードを取り出す。
fn decode_pem_seed(text: &str) -> Option<Vec<u8>> {
    let begin = text.find(PEM_BEGIN)?;
    let end = text.find(PEM_END)?;
    let body = text.get(begin + PEM_BEGIN.len()..end)?;
    let b64: String = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("Comment:"))
        .collect();
    BASE64
        .decode(b64.trim())
        .ok()
        .filter(|decoded| !decoded.is_empty())
}

fn generate_seed() -> Vec<u8> {
    let mut buf = vec![0u8; SEED_BYTES];
    getrandom::getrandom(&mut buf).expect("乱数生成に失敗しました");
    buf
}

/// シードをSSH秘密鍵やTLS証明書と同様のPEM風テキストとしてエンコードする。
/// BEGIN/ENDマーカーと警告コメントを含めることで、単なる乱数文字列ではなく
/// 秘密鍵として扱うべきファイルであることを見た目からも示す。
fn encode_seed(seed: &[u8]) -> String {
    let b64 = BASE64.encode(seed);
    let mut out = String::new();
    out.push_str(PEM_BEGIN);
    out.push('\n');
    out.push_str(PEM_WARNING);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(PEM_LINE_WIDTH) {
        // chunkはbase64文字（ASCII）のみで構成されるため常に有効なUTF-8
        out.push_str(std::str::from_utf8(chunk).expect("base64 chunk must be valid UTF-8"));
        out.push('\n');
    }
    out.push_str(PEM_END);
    out.push('\n');
    out
}

#[cfg(unix)]
fn save_seed(path: &PathBuf, seed: &[u8]) {
    if let Some(parent) = path.parent() {
        create_data_dir(parent);
    }
    let text = encode_seed(seed);
    // 既存のシードを上書きすると復元できないため、create_newで新規作成のみ許可する
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
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
        create_data_dir(parent);
    }
    let text = encode_seed(seed);
    // 既存のシードを上書きすると復元できないため、create_newで新規作成のみ許可する
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("シードファイルの作成に失敗しました");
    file.write_all(text.as_bytes())
        .expect("シードファイルへの書き込みに失敗しました");
}

/// シードファイルのパーミッションを検査する。
/// SSH秘密鍵と同様、所有者以外からの読み取りが可能な状態は情報漏洩のリスクがあるため、
/// グループ・その他に権限が付いている場合は実行を中止する。
/// 所有者の権限は問わない（旧バージョンで生成した 0600 のシードもそのまま使える）。
#[cfg(unix)]
fn check_seed_permissions(path: &PathBuf) {
    let metadata = fs::metadata(path).expect("シードファイルの情報取得に失敗しました");
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "エラー: シードファイルのパーミッションが不正です: {} (現在: {:04o}, 推奨: {:04o})",
            path.display(),
            mode,
            SEED_FILE_MODE
        );
        eprintln!(
            "秘密鍵と同様に扱う必要があるため、他ユーザーから読み取れない状態にしてください:"
        );
        eprintln!("  chmod {:o} {}", SEED_FILE_MODE, path.display());
        std::process::exit(1);
    }
}

/// シードファイルのアクセス権限を検査する（Windows版）。
/// Unix版のパーミッション検査（0600）に相当する検査をNTFSのACLに対して行う。
/// 所有者・Administrators・SYSTEM 以外のアカウントにアクセスを許可するACEが
/// 存在する場合、秘密鍵と同様に扱うべきファイルとして実行を中止する。
#[cfg(windows)]
fn check_seed_permissions(path: &std::path::Path) {
    use crate::winacl::{verify_owner_only, AclProblem};

    match verify_owner_only(path) {
        Ok(None) => {}
        Ok(Some(AclProblem::NoDacl)) => {
            eprintln!(
                "エラー: シードファイルのアクセス権限が不正です: {}",
                path.display()
            );
            eprintln!("DACLが設定されておらず、全アカウントからアクセス可能な状態です。");
            print_windows_fix_hint(path);
            std::process::exit(1);
        }
        Ok(Some(AclProblem::ExtraAccessGranted)) => {
            eprintln!(
                "エラー: シードファイルのアクセス権限が不正です: {}",
                path.display()
            );
            eprintln!(
                "所有者・Administrators・SYSTEM 以外のアカウントがアクセスできる状態になっています。"
            );
            print_windows_fix_hint(path);
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!(
                "エラー: シードファイルのアクセス権限を確認できませんでした: {}",
                path.display()
            );
            eprintln!("詳細: {}", err.0);
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn print_windows_fix_hint(path: &std::path::Path) {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "<ユーザー名>".to_string());
    eprintln!(
        "秘密鍵と同様に扱う必要があるため、他アカウントからアクセスできない状態にしてください:"
    );
    eprintln!(
        "  icacls \"{}\" /inheritance:r /grant:r \"{}\":F",
        path.display(),
        user
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("passgen-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_migrate_prefers_newest_legacy_path() {
        let dir = temp_dir("migrate");
        let newer = dir.join("config").join("passgen_seed");
        let older = dir.join(".pass-gen-seed");
        fs::create_dir_all(newer.parent().unwrap()).unwrap();
        fs::write(&newer, "newer").unwrap();
        fs::write(&older, "older").unwrap();

        let dest = dir.join("share").join("passgen").join("passgen_seed");
        migrate_legacy_seed(&dest, &[newer.clone(), older.clone()]);

        assert_eq!(fs::read_to_string(&dest).unwrap(), "newer");
        assert!(!newer.exists());
        assert!(older.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_migrate_without_legacy_seed_creates_nothing() {
        let dir = temp_dir("migrate-none");
        let dest = dir.join("share").join("passgen").join("passgen_seed");
        migrate_legacy_seed(&dest, &[dir.join("missing")]);

        assert!(!dest.exists());
        assert!(!dest.parent().unwrap().exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_saved_seed_is_read_only_in_private_dir() {
        let dir = temp_dir("save");
        let dest = dir.join("passgen").join("passgen_seed");
        let seed = generate_seed();
        save_seed(&dest, &seed);

        let file_mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(dest.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, SEED_FILE_MODE);
        assert_eq!(dir_mode, DATA_DIR_MODE);
        assert_eq!(decode_seed(&fs::read(&dest).unwrap()), seed);
        fs::remove_dir_all(&dir).unwrap();
    }
}

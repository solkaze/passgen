use std::fs;
use std::path::PathBuf;

// ============================================================
// ユーザー設定定数
// ============================================================

/// デフォルトのパスワード長
pub const DEFAULT_LENGTH: usize = 64;

/// デフォルトのPBKDF2イテレーション回数
pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// パスワード長の最小値
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// 導出キーの最小バイト数倍率
pub const KEY_LENGTH_MULTIPLIER: usize = 8;

/// 導出キーの最低保証バイト数
pub const KEY_LENGTH_MIN: usize = 64;

/// saltのサフィックス
pub const SALT_SUFFIX: &str = ":passgen";

/// Argon2idのデフォルトタイムコスト
pub const DEFAULT_ARGON2_TIME_COST: u32 = 3;

/// Argon2idのデフォルトメモリコスト（KiB単位、64 MiB）
pub const DEFAULT_ARGON2_MEMORY_COST_KIB: u32 = 65_536;

/// Argon2idのデフォルト並列度
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// コアパスワード入力プロンプト
pub const PROMPT_CORE_PASSWORD: &str = "コアパスワードを入力してください: ";

/// 設定ディレクトリ名（~/.config 配下）
pub const CONFIG_DIR_NAME: &str = "passgen";

/// シードファイル名
pub const SEED_FILE_NAME: &str = "passgen_seed";

/// 旧シードファイル名（ホーム直下、移行用）
pub const LEGACY_SEED_FILE_NAME: &str = ".pass-gen-seed";

/// シードファイルのパーミッション（Unix のみ）
#[cfg(unix)]
pub const SEED_FILE_MODE: u32 = 0o600;

/// シードのバイト長（512バイト = 4096bit。RSA-4096の秘密鍵と同等のビット数）
pub const SEED_BYTES: usize = 512;

/// サーバーのデフォルトポート
pub const DEFAULT_SERVER_PORT: u16 = 11010;

/// .env ファイル名（プロジェクトルートに配置）
pub const ENV_FILE_NAME: &str = ".env";

/// HTML ディレクトリ名（プロジェクトルート配下）
pub const HTML_DIR_NAME: &str = "html";

/// HTML ファイル名
pub const HTML_FILE_NAME: &str = "index.html";

// ============================================================
// 設定ディレクトリ・ファイルパス
// ============================================================

pub fn home_dir() -> PathBuf {
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
pub fn project_root() -> PathBuf {
    let exe = std::env::current_exe().expect("実行ファイルのパスを取得できません");
    exe.parent() // target/release
        .and_then(|p| p.parent()) // target
        .and_then(|p| p.parent()) // project root
        .expect("プロジェクトルートの解決に失敗しました")
        .to_path_buf()
}

pub fn env_file_path() -> PathBuf {
    project_root().join(ENV_FILE_NAME)
}

pub fn html_file_path() -> PathBuf {
    project_root().join(HTML_DIR_NAME).join(HTML_FILE_NAME)
}

/// 設定ディレクトリ（~/.config/passgen）を返す。
pub fn config_dir() -> PathBuf {
    home_dir().join(".config").join(CONFIG_DIR_NAME)
}

pub fn seed_file_path() -> PathBuf {
    config_dir().join(SEED_FILE_NAME)
}

/// 旧バージョンで使用していたシードファイルのパス（~/.pass-gen-seed）。
/// 新パスへの自動移行にのみ使用する。
pub fn legacy_seed_file_path() -> PathBuf {
    home_dir().join(LEGACY_SEED_FILE_NAME)
}

// ============================================================
// .env 処理
// ============================================================

/// .env を読み込んでポート番号を返す。なければデフォルト値で .env を自動生成する。
pub fn load_or_create_env() -> u16 {
    let env_path = env_file_path();

    if !env_path.exists() {
        eprintln!(
            ".env が見つかりません。デフォルト値で生成します: {}",
            env_path.display()
        );
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
pub fn load_html() -> String {
    let html_path = html_file_path();
    if !html_path.exists() {
        eprintln!(
            "エラー: index.html が見つかりません: {}",
            html_path.display()
        );
        eprintln!("プロジェクトの html/index.html が存在するか確認してください。");
        std::process::exit(1);
    }
    fs::read_to_string(&html_path).expect("index.html の読み込みに失敗しました")
}

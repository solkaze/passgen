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

/// 登録済みサイトの選択プロンプト
pub const PROMPT_SELECT_SITE: &str = "番号または登録名を入力してください: ";

/// 設定ディレクトリ名（~/.config 配下）
pub const CONFIG_DIR_NAME: &str = "passgen";

/// データディレクトリ名（~/.local/share 配下）
pub const DATA_DIR_NAME: &str = "passgen";

/// 設定ファイル名
pub const SETTINGS_FILE_NAME: &str = "settings.toml";

/// シードファイル名
pub const SEED_FILE_NAME: &str = "passgen_seed";

/// サイト登録リストのファイル名
pub const SITES_FILE_NAME: &str = "passgen_sites";

/// 旧シードファイル名（ホーム直下、移行用）
pub const LEGACY_SEED_FILE_NAME: &str = ".pass-gen-seed";

/// シードファイルのパーミッション（Unix のみ）。
/// 生成後に書き換えることはないため、誤上書きを防ぐ目的で所有者も読み取り専用とする。
#[cfg(unix)]
pub const SEED_FILE_MODE: u32 = 0o400;

/// サイト登録リストのパーミッション（Unix のみ）。登録・削除のたびに書き換える。
#[cfg(unix)]
pub const SITES_FILE_MODE: u32 = 0o600;

/// シードファイルを置くデータディレクトリのパーミッション（Unix のみ）
#[cfg(unix)]
pub const DATA_DIR_MODE: u32 = 0o700;

/// シードのバイト長（512バイト = 4096bit。RSA-4096の秘密鍵と同等のビット数）
pub const SEED_BYTES: usize = 512;

// ============================================================
// 設定ディレクトリ・ファイルパス
// ============================================================

pub fn home_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("ホームディレクトリが取得できません");
    PathBuf::from(home)
}

/// 設定ディレクトリ（~/.config/passgen）を返す。
/// ユーザーが編集する設定ファイルのみを置き、シードは置かない。
pub fn config_dir() -> PathBuf {
    home_dir().join(".config").join(CONFIG_DIR_NAME)
}

/// データディレクトリ（~/.local/share/passgen）を返す。
/// 設定ディレクトリは編集・削除・dotfiles管理の対象になりやすいため、
/// 失うと復元できないシードはこちらに分離して置く。
pub fn data_dir() -> PathBuf {
    home_dir().join(".local").join("share").join(DATA_DIR_NAME)
}

pub fn settings_file_path() -> PathBuf {
    config_dir().join(SETTINGS_FILE_NAME)
}

pub fn seed_file_path() -> PathBuf {
    data_dir().join(SEED_FILE_NAME)
}

/// サイト登録リストのパス。どのサービスにアカウントがあるかの一覧になるため、
/// dotfiles管理の対象になりやすい設定ディレクトリではなく、シードと同じ場所に置く。
pub fn sites_file_path() -> PathBuf {
    data_dir().join(SITES_FILE_NAME)
}

/// 旧バージョンで使用していたシードファイルのパス。新しいものから順に返す。
/// 新パスへの自動移行にのみ使用する。
pub fn legacy_seed_file_paths() -> Vec<PathBuf> {
    vec![
        config_dir().join(SEED_FILE_NAME),
        home_dir().join(LEGACY_SEED_FILE_NAME),
    ]
}

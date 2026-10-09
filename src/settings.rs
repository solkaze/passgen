use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::Deserialize;

use crate::config::{
    DEFAULT_ARGON2_MEMORY_COST_KIB, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ITERATIONS, DEFAULT_LENGTH,
};
use crate::kdf::KdfAlgorithm;

// ============================================================
// 設定ファイル（~/.config/passgen/settings.toml）
// ============================================================

/// 設定ファイルの内容。すべて省略可能で、省略した項目は組み込みのデフォルトが使われる。
/// 優先順位は「コマンドラインオプション > 設定ファイル > 組み込みのデフォルト」。
///
/// キー名の打ち間違いに気付かないまま別のパスワードが生成されるのを防ぐため、
/// 未知のキーはエラーとして扱う。
#[derive(Deserialize, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub length: Option<usize>,
    pub kdf: Option<KdfAlgorithm>,
    pub iterations: Option<u32>,
    pub time_cost: Option<u32>,
    pub memory_cost: Option<u32>,
    pub parallelism: Option<u32>,
    pub copy: Option<bool>,
    pub digits: Option<bool>,
    pub symbols: Option<bool>,
    #[serde(rename = "char")]
    pub custom_symbols: Option<String>,
}

fn parse(text: &str) -> Result<Settings, toml::de::Error> {
    toml::from_str(text)
}

/// 設定ファイルを読み込む。ファイルが存在しない場合は空の設定を返す。
pub fn load(path: &Path) -> Settings {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Settings::default(),
        Err(e) => {
            eprintln!(
                "エラー: 設定ファイルの読み込みに失敗しました: {}: {}",
                path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    match parse(&text) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("エラー: 設定ファイルの内容が不正です: {}", path.display());
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

/// 設定ファイルのテンプレート。全項目をコメントアウトした状態で出力するため、
/// 作成しただけでは生成されるパスワードは変わらない。
fn template() -> String {
    format!(
        r#"# passgen 設定ファイル
#
# ここに書いた値は、コマンドラインでオプションを省略したときの値として使われます。
# 優先順位: コマンドラインオプション > このファイル > 組み込みのデフォルト
#
# 注意: copy 以外の値を変えると、同じサイト名・コアパスワードでも
#       生成されるパスワードが変わります。

# 生成するパスワードの長さ
# length = {length}

# 鍵導出アルゴリズム（"argon2id" または "pbkdf2"）
# kdf = "argon2id"

# PBKDF2のイテレーション回数（kdf = "pbkdf2" の場合のみ使用）
# iterations = {iterations}

# Argon2idのタイムコスト（kdf = "argon2id" の場合のみ使用）
# time_cost = {time_cost}

# Argon2idのメモリコスト、KiB単位（kdf = "argon2id" の場合のみ使用）
# memory_cost = {memory_cost}

# Argon2idの並列度（kdf = "argon2id" の場合のみ使用）
# parallelism = {parallelism}

# 生成したパスワードをクリップボードにコピーする
# copy = false

# 数字を含める
# digits = true

# 記号を含める
# symbols = true

# 使用可能な記号（デフォルトの記号セットを置き換える）
# char = "!@#-_"
"#,
        length = DEFAULT_LENGTH,
        iterations = DEFAULT_ITERATIONS,
        time_cost = DEFAULT_ARGON2_TIME_COST,
        memory_cost = DEFAULT_ARGON2_MEMORY_COST_KIB,
        parallelism = DEFAULT_ARGON2_PARALLELISM,
    )
}

/// 設定ファイルが存在しない場合にテンプレートを作成する。
/// 作成した場合は true、既に存在していた場合は false を返す。既存ファイルは上書きしない。
pub fn create_template_if_missing(path: &Path) -> io::Result<bool> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(template().as_bytes())?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_file_is_default() {
        assert_eq!(parse("").unwrap(), Settings::default());
    }

    #[test]
    fn test_parse_all_keys() {
        let settings = parse(
            r#"
            length = 32
            kdf = "pbkdf2"
            iterations = 1000000
            time_cost = 5
            memory_cost = 131072
            parallelism = 2
            copy = true
            digits = false
            symbols = false
            char = "!@#"
            "#,
        )
        .unwrap();
        assert_eq!(
            settings,
            Settings {
                length: Some(32),
                kdf: Some(KdfAlgorithm::Pbkdf2),
                iterations: Some(1_000_000),
                time_cost: Some(5),
                memory_cost: Some(131_072),
                parallelism: Some(2),
                copy: Some(true),
                digits: Some(false),
                symbols: Some(false),
                custom_symbols: Some("!@#".to_string()),
            }
        );
    }

    #[test]
    fn test_unknown_key_is_rejected() {
        assert!(parse("lenght = 32").is_err());
    }

    #[test]
    fn test_invalid_kdf_is_rejected() {
        assert!(parse(r#"kdf = "scrypt""#).is_err());
    }

    #[test]
    fn test_template_changes_nothing() {
        assert_eq!(parse(&template()).unwrap(), Settings::default());
    }

    /// テンプレートのコメントを外した各行が、そのまま有効な設定として読めることを確認する。
    #[test]
    fn test_template_uncommented_is_valid() {
        let uncommented: String = template()
            .lines()
            .filter_map(|line| line.strip_prefix("# "))
            .filter(|line| {
                // 説明文の中の「kdf = "pbkdf2"」などを拾わないよう、キーで始まる行に限る
                line.split_once(" = ").is_some_and(|(key, _)| {
                    key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })
            })
            .map(|line| format!("{}\n", line))
            .collect();
        let settings = parse(&uncommented).unwrap();
        assert_eq!(settings.length, Some(DEFAULT_LENGTH));
        assert_eq!(settings.kdf, Some(KdfAlgorithm::Argon2id));
        assert_eq!(settings.custom_symbols.as_deref(), Some("!@#-_"));
    }
}

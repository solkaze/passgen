use std::fs;
use std::io::{self, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::cli::{AddArgs, GenArgs};
use crate::config::{self, MIN_PASSWORD_LENGTH};
use crate::kdf::KdfAlgorithm;
use crate::{seed, site};

#[cfg(unix)]
use crate::config::SITES_FILE_MODE;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

// ============================================================
// サイト登録リスト（~/.local/share/passgen/passgen_sites）
// ============================================================

/// サイトごとに保存する生成条件。指定されなかった項目は None のまま保存し、
/// 生成時に設定ファイルと組み込みのデフォルトで補う。
/// 優先順位は「コマンドラインオプション > 登録内容 > 設定ファイル > 組み込みのデフォルト」。
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct SiteOptions {
    pub length: Option<usize>,
    pub kdf: Option<KdfAlgorithm>,
    pub iterations: Option<u32>,
    pub time_cost: Option<u32>,
    pub memory_cost: Option<u32>,
    pub parallelism: Option<u32>,
    pub digits: Option<bool>,
    pub symbols: Option<bool>,
    #[serde(rename = "char")]
    pub custom_symbols: Option<String>,
}

impl SiteOptions {
    /// add のオプションから登録内容を作る。生成時にエラーになる値はここで弾く。
    fn from_args(args: &GenArgs) -> Self {
        if let Some(length) = args.length {
            if length < MIN_PASSWORD_LENGTH {
                eprintln!(
                    "エラー: パスワード長は{}文字以上を指定してください。",
                    MIN_PASSWORD_LENGTH
                );
                std::process::exit(1);
            }
        }
        if let Some(custom) = &args.custom_symbols {
            crate::parse_custom_symbols(custom, "-C/--char");
        }

        // -C/--char を指定した場合は、生成時と同じく記号を使う意図とみなして常に有効にする
        let symbols = if args.custom_symbols.is_some() {
            if args.no_symbols {
                eprintln!("警告: --no-symbols が指定されていますが、-C/--char が指定されたため記号を使用します。");
            }
            Some(true)
        } else {
            flag(args.symbols, args.no_symbols)
        };

        SiteOptions {
            length: args.length,
            kdf: args.kdf,
            iterations: args.iterations,
            time_cost: args.argon2_time_cost,
            memory_cost: args.argon2_memory_cost,
            parallelism: args.argon2_parallelism,
            digits: flag(args.digits, args.no_digits),
            symbols,
            custom_symbols: args.custom_symbols.clone(),
        }
    }

    /// 保存されている項目を `length=32, char="!@#"` の形で並べる。何もなければ空文字列。
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(v) = self.length {
            parts.push(format!("length={}", v));
        }
        if let Some(v) = self.kdf {
            parts.push(format!("kdf={}", v));
        }
        if let Some(v) = self.iterations {
            parts.push(format!("iterations={}", v));
        }
        if let Some(v) = self.time_cost {
            parts.push(format!("time_cost={}", v));
        }
        if let Some(v) = self.memory_cost {
            parts.push(format!("memory_cost={}", v));
        }
        if let Some(v) = self.parallelism {
            parts.push(format!("parallelism={}", v));
        }
        if let Some(v) = self.digits {
            parts.push(format!("digits={}", v));
        }
        if let Some(v) = self.symbols {
            parts.push(format!("symbols={}", v));
        }
        if let Some(v) = &self.custom_symbols {
            parts.push(format!("char={:?}", v));
        }
        parts.join(", ")
    }
}

fn flag(on: bool, off: bool) -> Option<bool> {
    if on {
        Some(true)
    } else if off {
        Some(false)
    } else {
        None
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SiteEntry {
    /// 生成時に指定する登録名
    pub name: String,
    /// saltに使うサイト名
    pub site: String,
    #[serde(default)]
    pub options: SiteOptions,
}

#[derive(Serialize, Deserialize, Default)]
struct SiteList {
    #[serde(default)]
    sites: Vec<SiteEntry>,
}

// ============================================================
// 暗号化
// ============================================================

// リストは「どのサービスにアカウントがあるか」の一覧になるため、ファイル単体が
// バックアップや同期先に出ても読めないよう、シードから導出した鍵で暗号化する。
//
// コアパスワードは鍵に使わない。使うと「復号できたら正しいコアパスワード」という
// 照合手段を手元のファイルに残すことになり、シードとリストを得た攻撃者が
// オフラインで総当たりできるようになるため。

/// ファイル先頭の識別子。形式を変える場合は末尾の番号を上げる。
const MAGIC: &[u8] = b"PASSGEN-SITES-1\n";
/// 鍵導出のラベル。パスワード生成に使う値と鍵が重ならないよう、用途を固定する。
const KEY_INFO: &[u8] = b"passgen sites list v1";
const NONCE_LEN: usize = 24;

fn cipher(seed: &[u8]) -> XChaCha20Poly1305 {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed)
        .expand(KEY_INFO, &mut key)
        .expect("鍵の導出に失敗しました");
    XChaCha20Poly1305::new(&key.into())
}

fn encrypt(seed: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("乱数生成に失敗しました");
    let ciphertext = cipher(seed)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC,
            },
        )
        .expect("サイト登録リストの暗号化に失敗しました");

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// 復号する。形式が違う、シードが違う、改ざんされている場合は None を返す。
fn decrypt(seed: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let rest = data.strip_prefix(MAGIC)?;
    if rest.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    cipher(seed)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .ok()
}

// ============================================================
// 読み込み・保存
// ============================================================

fn decode(seed: &[u8], data: &[u8]) -> Option<Vec<SiteEntry>> {
    let plaintext = decrypt(seed, data)?;
    let text = String::from_utf8(plaintext).ok()?;
    let list: SiteList = toml::from_str(&text).ok()?;
    Some(list.sites)
}

fn encode(seed: &[u8], entries: &[SiteEntry]) -> Vec<u8> {
    let list = SiteList {
        sites: entries.to_vec(),
    };
    let text = toml::to_string(&list).expect("サイト登録リストの変換に失敗しました");
    encrypt(seed, text.as_bytes())
}

/// サイト登録リストを読み込む。ファイルが存在しない場合は空のリストを返す。
pub fn load(path: &Path, seed: &[u8]) -> Vec<SiteEntry> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            eprintln!(
                "エラー: サイト登録リストの読み込みに失敗しました: {}: {}",
                path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    match decode(seed, &data) {
        Some(entries) => entries,
        None => {
            eprintln!(
                "エラー: サイト登録リストを復号できません: {}",
                path.display()
            );
            eprintln!("別のシードで作成されたファイルか、内容が壊れている可能性があります。");
            eprintln!(
                "登録内容を使わずに生成する場合は、-s でサイト名を指定して --raw を付けてください。"
            );
            std::process::exit(1);
        }
    }
}

fn save(path: &Path, seed: &[u8], entries: &[SiteEntry]) {
    if let Some(parent) = path.parent() {
        seed::create_data_dir(parent);
    }
    if let Err(e) = write_private(path, &encode(seed, entries)) {
        eprintln!(
            "エラー: サイト登録リストの保存に失敗しました: {}: {}",
            path.display(),
            e
        );
        std::process::exit(1);
    }
}

/// 所有者のみが読み書きできるファイルとして書き込む。
/// 書き込みが途中で失敗しても既存のリストが壊れないよう、
/// 一時ファイルへ書いてからrenameで確定させる。
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    // 残っていた一時ファイルのパーミッションを引き継がないよう、作り直す
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(SITES_FILE_MODE);

    let mut file = options.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

// ============================================================
// 検索・選択
// ============================================================

/// `-s` の指定から登録済みのサイトを探す。
/// 登録名に一致するものを優先し、なければ正規化したサイト名で照合する
/// （ブラウザのURLを貼り付けても同じ登録に一致させるため）。
pub fn find<'a>(entries: &'a [SiteEntry], input: &str) -> Option<&'a SiteEntry> {
    entries.iter().find(|e| e.name == input).or_else(|| {
        let normalized = site::normalize(input);
        entries.iter().find(|e| e.site == normalized)
    })
}

/// 登録名とサイト名が既存の登録と紛らわしくならないことを確認する。
/// 登録名とサイト名のどちらでも検索できるため、両方をまたいで重複を禁止する。
fn check_conflict(entries: &[SiteEntry], name: &str, site: &str) -> Result<(), String> {
    for e in entries {
        if e.name == name || e.site == name {
            return Err(format!(
                "登録名 {:?} は既に使われています（{} -> {}）。",
                name, e.name, e.site
            ));
        }
        if e.site == site || e.name == site {
            return Err(format!(
                "サイト {:?} は既に登録されています（{} -> {}）。",
                site, e.name, e.site
            ));
        }
    }
    Ok(())
}

/// 一覧の各行を「登録名  サイト名  (登録内容)」の形に整える。
fn format_rows(entries: &[SiteEntry]) -> Vec<String> {
    let name_width = entries
        .iter()
        .map(|e| e.name.chars().count())
        .max()
        .unwrap_or(0);
    let site_width = entries
        .iter()
        .map(|e| e.site.chars().count())
        .max()
        .unwrap_or(0);

    entries
        .iter()
        .map(|e| {
            let summary = e.options.summary();
            let row = if summary.is_empty() {
                format!("{:<name_width$}  {}", e.name, e.site)
            } else {
                format!(
                    "{:<name_width$}  {:<site_width$}  ({})",
                    e.name, e.site, summary
                )
            };
            row.trim_end().to_string()
        })
        .collect()
}

/// 一覧での入力（番号または登録名）から、選ばれた登録の位置を求める。
fn parse_selection(entries: &[SiteEntry], input: &str) -> Option<usize> {
    if let Ok(number) = input.parse::<usize>() {
        return (1..=entries.len()).contains(&number).then(|| number - 1);
    }
    entries.iter().position(|e| e.name == input)
}

/// 登録済みのサイトを一覧表示し、対話的に1つ選ばせる。
/// 生成結果だけを標準出力に出せるよう、一覧とプロンプトは標準エラー出力に書く。
pub fn pick(entries: &[SiteEntry]) -> &SiteEntry {
    let number_width = entries.len().to_string().len();
    for (i, row) in format_rows(entries).iter().enumerate() {
        eprintln!("{:>number_width$}) {}", i + 1, row);
    }

    loop {
        eprint!("{}", config::PROMPT_SELECT_SITE);
        io::stderr().flush().expect("出力エラー");

        let mut line = String::new();
        let read = io::stdin().read_line(&mut line).expect("入力エラー");
        let input = line.trim();
        if read == 0 || input.is_empty() {
            eprintln!("キャンセルしました。");
            std::process::exit(1);
        }

        match parse_selection(entries, input) {
            Some(index) => return &entries[index],
            None => eprintln!("該当するサイトがありません: {}", input),
        }
    }
}

// ============================================================
// サブコマンド
// ============================================================

fn load_seed() -> Vec<u8> {
    seed::load_or_create_seed(&config::seed_file_path())
}

pub fn run_add(args: AddArgs) {
    let site = if args.raw {
        args.site.clone()
    } else {
        site::normalize(&args.site)
    };
    if site.is_empty() {
        eprintln!("エラー: サイト名が空です。");
        std::process::exit(1);
    }

    let name = args.name.clone().unwrap_or_else(|| site.clone());
    if name.is_empty() {
        eprintln!("エラー: 登録名が空です。");
        std::process::exit(1);
    }
    // 数字だけの登録名は、一覧から選ぶときの番号と区別できない
    if name.bytes().all(|b| b.is_ascii_digit()) {
        eprintln!("エラー: 数字だけの登録名は使えません。");
        std::process::exit(1);
    }

    let options = SiteOptions::from_args(&args.options);

    let seed = load_seed();
    let path = config::sites_file_path();
    let mut entries = load(&path, &seed);
    if let Err(message) = check_conflict(&entries, &name, &site) {
        eprintln!("エラー: {}", message);
        eprintln!("内容を変える場合は、passgen remove で削除してから登録し直してください。");
        std::process::exit(1);
    }

    let entry = SiteEntry {
        name,
        site,
        options,
    };
    let row = format_rows(std::slice::from_ref(&entry)).remove(0);
    entries.push(entry);
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    save(&path, &seed, &entries);

    println!("登録しました: {}", row);
}

pub fn run_list() {
    let entries = load(&config::sites_file_path(), &load_seed());
    if entries.is_empty() {
        println!("登録されているサイトはありません。passgen add <URL> で登録できます。");
        return;
    }
    for row in format_rows(&entries) {
        println!("{}", row);
    }
}

pub fn run_remove(name: &str) {
    let seed = load_seed();
    let path = config::sites_file_path();
    let mut entries = load(&path, &seed);

    let Some(index) = entries.iter().position(|e| e.name == name) else {
        eprintln!("エラー: {:?} は登録されていません。", name);
        eprintln!("登録名は passgen list で確認できます。");
        std::process::exit(1);
    };
    let removed = entries.remove(index);
    save(&path, &seed, &entries);

    println!("削除しました: {} -> {}", removed.name, removed.site);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SEED_BYTES;

    fn entry(name: &str, site: &str) -> SiteEntry {
        SiteEntry {
            name: name.to_string(),
            site: site.to_string(),
            options: SiteOptions::default(),
        }
    }

    fn sample() -> Vec<SiteEntry> {
        vec![
            SiteEntry {
                name: "bank".to_string(),
                site: "bank.example.com".to_string(),
                options: SiteOptions {
                    length: Some(32),
                    kdf: Some(KdfAlgorithm::Pbkdf2),
                    symbols: Some(true),
                    custom_symbols: Some("!@#-_".to_string()),
                    ..SiteOptions::default()
                },
            },
            entry("github.com", "github.com"),
        ]
    }

    #[test]
    fn test_roundtrip() {
        let seed = vec![7u8; SEED_BYTES];
        let entries = sample();
        assert_eq!(decode(&seed, &encode(&seed, &entries)), Some(entries));
    }

    #[test]
    fn test_empty_list_roundtrip() {
        let seed = vec![7u8; SEED_BYTES];
        assert_eq!(decode(&seed, &encode(&seed, &[])), Some(Vec::new()));
    }

    #[test]
    fn test_file_does_not_contain_site_names() {
        let seed = vec![7u8; SEED_BYTES];
        let data = encode(&seed, &sample());
        let needle = b"example.com";
        assert!(!data.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn test_other_seed_cannot_decrypt() {
        let data = encode(&vec![7u8; SEED_BYTES], &sample());
        assert_eq!(decode(&vec![8u8; SEED_BYTES], &data), None);
    }

    #[test]
    fn test_tampered_data_is_rejected() {
        let seed = vec![7u8; SEED_BYTES];
        let mut data = encode(&seed, &sample());
        let last = data.len() - 1;
        data[last] ^= 1;
        assert_eq!(decode(&seed, &data), None);
        assert_eq!(decode(&seed, b"not a sites file"), None);
        assert_eq!(decode(&seed, MAGIC), None);
    }

    #[test]
    fn test_find_by_name_or_url() {
        let entries = sample();
        assert_eq!(find(&entries, "bank").unwrap().site, "bank.example.com");
        assert_eq!(
            find(&entries, "https://Bank.Example.com/login")
                .unwrap()
                .name,
            "bank"
        );
        assert_eq!(find(&entries, "www.github.com").unwrap().name, "github.com");
        assert!(find(&entries, "gitlab.com").is_none());
        assert!(find(&entries, "").is_none());
    }

    #[test]
    fn test_conflicts() {
        let entries = sample();
        assert!(check_conflict(&entries, "gitlab", "gitlab.com").is_ok());
        assert!(check_conflict(&entries, "bank", "other.example.com").is_err());
        assert!(check_conflict(&entries, "bank2", "bank.example.com").is_err());
        // 登録名が別の登録のサイト名と同じ、またはその逆も紛らわしいため禁止する
        assert!(check_conflict(&entries, "github.com", "other.example.com").is_err());
        assert!(check_conflict(&entries, "other", "bank").is_err());
    }

    #[test]
    fn test_parse_selection() {
        let entries = sample();
        assert_eq!(parse_selection(&entries, "1"), Some(0));
        assert_eq!(parse_selection(&entries, "2"), Some(1));
        assert_eq!(parse_selection(&entries, "0"), None);
        assert_eq!(parse_selection(&entries, "3"), None);
        assert_eq!(parse_selection(&entries, "github.com"), Some(1));
        assert_eq!(parse_selection(&entries, "unknown"), None);
    }

    #[test]
    fn test_format_rows() {
        assert_eq!(
            format_rows(&sample()),
            vec![
                "bank        bank.example.com  (length=32, kdf=pbkdf2, symbols=true, char=\"!@#-_\")",
                "github.com  github.com",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_saved_file_is_private_and_replaceable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("passgen-test-sites-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("passgen").join("passgen_sites");
        let seed = vec![7u8; SEED_BYTES];

        assert_eq!(load(&path, &seed), Vec::new());
        save(&path, &seed, &sample());
        save(&path, &seed, &sample()[..1]);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SITES_FILE_MODE);
        assert_eq!(load(&path, &seed), sample()[..1].to_vec());
        assert!(!path.with_extension("tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}

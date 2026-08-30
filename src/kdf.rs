use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

use crate::config::{KEY_LENGTH_MIN, KEY_LENGTH_MULTIPLIER, SALT_SUFFIX};

// ============================================================
// 鍵導出アルゴリズム
// ============================================================

/// 鍵導出に使用するアルゴリズム。
/// 新規デフォルトは Argon2id。PBKDF2 は旧バージョンで生成したパスワードを
/// 再現するための互換用として残している。
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Pbkdf2,
    Argon2id,
}

impl std::fmt::Display for KdfAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KdfAlgorithm::Pbkdf2 => "pbkdf2",
            KdfAlgorithm::Argon2id => "argon2id",
        };
        write!(f, "{}", s)
    }
}

// ============================================================
// 文字セット定数
// ============================================================

pub const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const DIGITS: &[u8] = b"0123456789";
pub const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

const ENSURE_DIGITS_POS_OFFSET: usize = 2;
const ENSURE_DIGITS_CHAR_OFFSET: usize = 3;
const ENSURE_SYMBOLS_POS_OFFSET: usize = 3;
const ENSURE_SYMBOLS_CHAR_OFFSET: usize = 4;

// ============================================================
// コア処理
// ============================================================

pub fn build_core(core: &str, seed: &[u8]) -> String {
    let seed_hex: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}:{}", seed_hex, core)
}

pub fn derive_key(core: &str, salt: &str, iterations: u32, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    pbkdf2::<Hmac<Sha256>>(core.as_bytes(), salt.as_bytes(), iterations, &mut key)
        .expect("PBKDF2 failed");
    key
}

/// Argon2id で鍵を導出する。
/// `memory_cost` は KiB 単位。
pub fn derive_key_argon2id(
    core: &str,
    salt: &str,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    key_len: usize,
) -> Vec<u8> {
    let params = Params::new(memory_cost, time_cost, parallelism, Some(key_len))
        .expect("Argon2id パラメータが不正です");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; key_len];
    argon2
        .hash_password_into(core.as_bytes(), salt.as_bytes(), &mut key)
        .expect("Argon2id の鍵導出に失敗しました");
    key
}

/// key_bytes をパスワード文字列に変換する。
/// `symbols` には記号として使用する文字集合を渡す（use_symbols が true の場合のみ使用される）。
/// デフォルトの記号セットを使う場合は SYMBOLS 定数を渡し、
/// サイト固有の制限がある場合は呼び出し側で用意したカスタム記号セットを渡す。
pub fn bytes_to_password(
    key_bytes: &[u8],
    length: usize,
    use_digits: bool,
    use_symbols: bool,
    symbols: &[u8],
) -> String {
    let all_chars: Vec<u8> = [
        Some(UPPERCASE),
        Some(LOWERCASE),
        if use_digits { Some(DIGITS) } else { None },
        if use_symbols { Some(symbols) } else { None },
    ]
    .iter()
    .flatten()
    .flat_map(|s| s.iter().copied())
    .collect();
    let total = all_chars.len();

    let mut raw: Vec<u8> = key_bytes
        .chunks(8)
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
    if use_digits {
        ensure_sets.push((DIGITS, ENSURE_DIGITS_POS_OFFSET, ENSURE_DIGITS_CHAR_OFFSET));
    }
    if use_symbols {
        ensure_sets.push((
            symbols,
            ENSURE_SYMBOLS_POS_OFFSET,
            ENSURE_SYMBOLS_CHAR_OFFSET,
        ));
    }

    for (charset, pos_offset, char_offset) in &ensure_sets {
        let already_present = raw.iter().any(|c| charset.contains(c));
        if !already_present {
            let pos = key_bytes[pos_offset % key_bytes.len()] as usize % length;
            let ch = key_bytes[char_offset % key_bytes.len()] as usize % charset.len();
            raw[pos] = charset[ch];
        }
    }
    String::from_utf8(raw).expect("Invalid UTF-8 in password")
}

/// パスワード生成の各種オプションをまとめた構造体。
/// generate_password の引数がclippyのtoo_many_arguments閾値を超えないよう、
/// core/site/seed（対象の識別情報）以外の生成条件をここに集約する。
pub struct GenerateOptions<'a> {
    pub length: usize,
    pub kdf: KdfAlgorithm,
    /// PBKDF2 のイテレーション回数（kdf が Pbkdf2 の場合のみ使用）
    pub pbkdf2_iterations: u32,
    /// Argon2id のタイムコスト（kdf が Argon2id の場合のみ使用）
    pub argon2_time_cost: u32,
    /// Argon2id のメモリコスト、KiB単位（kdf が Argon2id の場合のみ使用）
    pub argon2_memory_cost: u32,
    /// Argon2id の並列度（kdf が Argon2id の場合のみ使用）
    pub argon2_parallelism: u32,
    pub use_digits: bool,
    pub use_symbols: bool,
    pub symbols: &'a [u8],
}

pub fn generate_password(core: &str, site: &str, seed: &[u8], opts: &GenerateOptions) -> String {
    let combined_core = build_core(core, seed);
    let salt = format!("{}{}", site, SALT_SUFFIX);
    let key_len = (opts.length * KEY_LENGTH_MULTIPLIER).max(KEY_LENGTH_MIN);
    let key = match opts.kdf {
        KdfAlgorithm::Pbkdf2 => derive_key(&combined_core, &salt, opts.pbkdf2_iterations, key_len),
        KdfAlgorithm::Argon2id => derive_key_argon2id(
            &combined_core,
            &salt,
            opts.argon2_time_cost,
            opts.argon2_memory_cost,
            opts.argon2_parallelism,
            key_len,
        ),
    };
    bytes_to_password(
        &key,
        opts.length,
        opts.use_digits,
        opts.use_symbols,
        opts.symbols,
    )
}

// ============================================================
// テスト
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_ITERATIONS, DEFAULT_LENGTH, MIN_PASSWORD_LENGTH, SEED_BYTES};

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
        assert_eq!(
            bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS),
            bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS)
        );
    }

    #[test]
    fn test_default_length() {
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("mysecret", "example.com", DEFAULT_ITERATIONS, &seed);
        assert_eq!(
            bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS)
                .chars()
                .count(),
            DEFAULT_LENGTH
        );
    }

    #[test]
    fn test_different_sites() {
        let seed = vec![0u8; SEED_BYTES];
        let key1 = test_key_direct("mysecret", "siteA", DEFAULT_ITERATIONS, &seed);
        let key2 = test_key_direct("mysecret", "siteB", DEFAULT_ITERATIONS, &seed);
        assert_ne!(
            bytes_to_password(&key1, DEFAULT_LENGTH, true, true, SYMBOLS),
            bytes_to_password(&key2, DEFAULT_LENGTH, true, true, SYMBOLS)
        );
    }

    #[test]
    fn test_contains_digit_and_symbol() {
        let seed = vec![0u8; SEED_BYTES];
        let key = test_key_direct("testmaster", "testsite", 10_000, &seed);
        let p = bytes_to_password(&key, DEFAULT_LENGTH, true, true, SYMBOLS);
        assert!(
            p.chars().any(|c| c.is_ascii_digit()),
            "数字が含まれていない"
        );
        assert!(
            p.chars().any(|c| SYMBOLS.contains(&(c as u8))),
            "記号が含まれていない"
        );
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
        assert_ne!(
            bytes_to_password(&key1, DEFAULT_LENGTH, true, true, SYMBOLS),
            bytes_to_password(&key2, DEFAULT_LENGTH, true, true, SYMBOLS)
        );
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
            let allowed = UPPERCASE.contains(&c)
                || LOWERCASE.contains(&c)
                || DIGITS.contains(&c)
                || custom.contains(&c);
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

    fn test_opts(kdf: KdfAlgorithm) -> GenerateOptions<'static> {
        GenerateOptions {
            length: 16,
            kdf,
            pbkdf2_iterations: 10_000,
            argon2_time_cost: 1,
            argon2_memory_cost: 8_192,
            argon2_parallelism: 1,
            use_digits: true,
            use_symbols: true,
            symbols: SYMBOLS,
        }
    }

    #[test]
    fn test_argon2id_deterministic() {
        let key1 = derive_key_argon2id("core", "salt:passgen", 1, 8_192, 1, 32);
        let key2 = derive_key_argon2id("core", "salt:passgen", 1, 8_192, 1, 32);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_argon2id_different_sites() {
        let key1 = derive_key_argon2id("core", "siteA:passgen", 1, 8_192, 1, 32);
        let key2 = derive_key_argon2id("core", "siteB:passgen", 1, 8_192, 1, 32);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_password_kdf_dispatch() {
        let seed = vec![0u8; SEED_BYTES];
        let pbkdf2_password =
            generate_password("mysecret", "example.com", &seed, &test_opts(KdfAlgorithm::Pbkdf2));
        let argon2_password = generate_password(
            "mysecret",
            "example.com",
            &seed,
            &test_opts(KdfAlgorithm::Argon2id),
        );
        assert_ne!(pbkdf2_password, argon2_password);
        assert_eq!(pbkdf2_password.chars().count(), 16);
        assert_eq!(argon2_password.chars().count(), 16);
    }
}

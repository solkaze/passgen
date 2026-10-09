mod cli;
mod clipboard;
mod config;
mod init;
mod input;
mod kdf;
mod seed;
mod settings;
#[cfg(windows)]
mod winacl;

use clap::Parser;

use cli::{Args, Commands};
use config::{
    DEFAULT_ARGON2_MEMORY_COST_KIB, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ITERATIONS, DEFAULT_LENGTH, MIN_PASSWORD_LENGTH,
};
use kdf::{generate_password, GenerateOptions, KdfAlgorithm, SYMBOLS};

/// 「有効にする」「無効にする」の対になったフラグを解決する。
/// どちらも指定されていなければ設定ファイルの値、それもなければデフォルト値を使う。
fn resolve_flag(on: bool, off: bool, setting: Option<bool>, default: bool) -> bool {
    if on {
        true
    } else if off {
        false
    } else {
        setting.unwrap_or(default)
    }
}

/// 記号セットの指定を検証し、重複を除いたバイト列にする。
/// `source` はエラーメッセージに表示する指定元（オプション名または設定ファイルのキー名）。
fn parse_custom_symbols(custom: &str, source: &str) -> Vec<u8> {
    if custom.is_empty() {
        eprintln!("エラー: {} には1文字以上指定してください。", source);
        std::process::exit(1);
    }
    if !custom.is_ascii() {
        eprintln!("エラー: {} はASCII文字のみ指定できます。", source);
        std::process::exit(1);
    }

    // 重複文字を除去する（入力順は保持）。重複があっても動作上問題はないが、
    // 同じ文字が複数枠を占めることによる分布の偏りを避けるため除去する。
    let mut seen = std::collections::HashSet::new();
    custom.bytes().filter(|b| seen.insert(*b)).collect()
}

fn main() {
    let args = Args::parse();

    if let Some(Commands::Init) = args.command {
        init::run_init();
        return;
    }

    let settings = settings::load(&config::settings_file_path());

    let seed_path = config::seed_file_path();
    let seed = seed::load_or_create_seed(&seed_path);

    // コマンドラインオプション > 設定ファイル > 組み込みのデフォルト の順で値を決める
    let length = args.length.or(settings.length).unwrap_or(DEFAULT_LENGTH);
    let kdf = args.kdf.or(settings.kdf).unwrap_or(KdfAlgorithm::Argon2id);
    let pbkdf2_iterations = args
        .iterations
        .or(settings.iterations)
        .unwrap_or(DEFAULT_ITERATIONS);
    let argon2_time_cost = args
        .argon2_time_cost
        .or(settings.time_cost)
        .unwrap_or(DEFAULT_ARGON2_TIME_COST);
    let argon2_memory_cost = args
        .argon2_memory_cost
        .or(settings.memory_cost)
        .unwrap_or(DEFAULT_ARGON2_MEMORY_COST_KIB);
    let argon2_parallelism = args
        .argon2_parallelism
        .or(settings.parallelism)
        .unwrap_or(DEFAULT_ARGON2_PARALLELISM);
    let copy = resolve_flag(args.copy, args.no_copy, settings.copy, false);
    let use_digits = resolve_flag(args.digits, args.no_digits, settings.digits, true);

    // CLIモード
    if length < MIN_PASSWORD_LENGTH {
        eprintln!(
            "エラー: パスワード長は{}文字以上を指定してください。",
            MIN_PASSWORD_LENGTH
        );
        std::process::exit(1);
    }

    // 記号セットを決める。-C/--char または設定ファイルの char が指定された場合、
    // デフォルトの記号セットを置き換える。
    let symbols: Vec<u8> = match (&args.custom_symbols, &settings.custom_symbols) {
        (Some(custom), _) => parse_custom_symbols(custom, "-C/--char"),
        (None, Some(custom)) => parse_custom_symbols(custom, "設定ファイルの char"),
        (None, None) => SYMBOLS.to_vec(),
    };

    // -C/--char をコマンドラインで指定した場合は、記号を使う意図とみなして常に有効にする
    let use_symbols = if args.custom_symbols.is_some() {
        if args.no_symbols {
            eprintln!("警告: --no-symbols が指定されていますが、-C/--char が指定されたため記号を使用します。");
        }
        true
    } else {
        resolve_flag(args.symbols, args.no_symbols, settings.symbols, true)
    };

    let core = input::prompt_masked(config::PROMPT_CORE_PASSWORD);
    if core.is_empty() {
        eprintln!("エラー: コアパスワードが空です。");
        std::process::exit(1);
    }

    let kdf_detail = match kdf {
        KdfAlgorithm::Pbkdf2 => format!("iterations={}", pbkdf2_iterations),
        KdfAlgorithm::Argon2id => format!(
            "time_cost={}, memory_cost={}KiB, parallelism={}",
            argon2_time_cost, argon2_memory_cost, argon2_parallelism
        ),
    };
    eprintln!(
        "生成中... (site={:?}, length={}, kdf={}, {}, digits={}, symbols={})",
        if args.site.is_empty() {
            "(なし)"
        } else {
            &args.site
        },
        length,
        kdf,
        kdf_detail,
        use_digits,
        use_symbols,
    );

    let opts = GenerateOptions {
        length,
        kdf,
        pbkdf2_iterations,
        argon2_time_cost,
        argon2_memory_cost,
        argon2_parallelism,
        use_digits,
        use_symbols,
        symbols: &symbols,
    };
    let password = generate_password(&core, &args.site, &seed, &opts);
    let border = "-".repeat(password.len());
    eprintln!("{}", border);
    println!("{}", password);
    eprintln!("{}", border);

    if copy {
        clipboard::copy_to_clipboard(&password);
    }
}

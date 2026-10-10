mod cli;
mod clipboard;
mod config;
mod init;
mod input;
mod kdf;
mod seed;
mod settings;
mod site;
mod sites;
#[cfg(windows)]
mod winacl;

use std::io::IsTerminal;

use clap::Parser;

use cli::{Args, Commands};
use config::{
    DEFAULT_ARGON2_MEMORY_COST_KIB, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ITERATIONS, DEFAULT_LENGTH, MIN_PASSWORD_LENGTH,
};
use kdf::{generate_password, GenerateOptions, KdfAlgorithm, SYMBOLS};
use sites::SiteOptions;

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

/// saltに使うサイト名と、そのサイトの登録内容を決める。
///
/// - `--raw`: `-s` の文字列をそのまま使い、登録内容は参照しない
/// - `-s` あり: 登録済みならその内容を使い、未登録なら正規化したサイト名を使う
/// - `-s` なし: 登録済みのサイトから対話的に選ぶ
fn resolve_site(args: &Args, seed: &[u8]) -> (String, SiteOptions) {
    if args.raw {
        // clap の requires により、--raw には必ず -s が伴う
        return (args.site.clone().unwrap_or_default(), SiteOptions::default());
    }

    let entries = sites::load(&config::sites_file_path(), seed);
    let Some(input) = &args.site else {
        if entries.is_empty() {
            eprintln!("エラー: サイトが登録されていません。");
            eprintln!(
                "passgen add <URL> で登録するか、-s でサイト名を指定してください（例: passgen -s github.com）。"
            );
            std::process::exit(1);
        }
        if !std::io::stdin().is_terminal() {
            eprintln!("エラー: 対話的に選択できないため、-s でサイト名を指定してください。");
            std::process::exit(1);
        }
        let entry = sites::pick(&entries);
        return (entry.site.clone(), entry.options.clone());
    };

    if let Some(entry) = sites::find(&entries, input) {
        return (entry.site.clone(), entry.options.clone());
    }

    let site = site::normalize(input);
    // リストを使っている場合に限り、打ち間違いに気付けるよう未登録であることを知らせる
    if !entries.is_empty() && !site.is_empty() {
        eprintln!(
            "警告: {:?} は登録されていません。このまま生成します（登録する場合: passgen add {}）。",
            site, site
        );
    }
    (site, SiteOptions::default())
}

fn main() {
    let mut args = Args::parse();

    match args.command.take() {
        Some(Commands::Init) => return init::run_init(),
        Some(Commands::Add(add)) => return sites::run_add(add),
        Some(Commands::List) => return sites::run_list(),
        Some(Commands::Remove { name }) => return sites::run_remove(&name),
        None => {}
    }

    let settings = settings::load(&config::settings_file_path());

    let seed_path = config::seed_file_path();
    let seed = seed::load_or_create_seed(&seed_path);

    let (site, site_opts) = resolve_site(&args, &seed);
    let opts = &args.options;

    // コマンドラインオプション > サイトの登録内容 > 設定ファイル > 組み込みのデフォルト
    // の順で値を決める
    let length = opts
        .length
        .or(site_opts.length)
        .or(settings.length)
        .unwrap_or(DEFAULT_LENGTH);
    let kdf = opts
        .kdf
        .or(site_opts.kdf)
        .or(settings.kdf)
        .unwrap_or(KdfAlgorithm::Argon2id);
    let pbkdf2_iterations = opts
        .iterations
        .or(site_opts.iterations)
        .or(settings.iterations)
        .unwrap_or(DEFAULT_ITERATIONS);
    let argon2_time_cost = opts
        .argon2_time_cost
        .or(site_opts.time_cost)
        .or(settings.time_cost)
        .unwrap_or(DEFAULT_ARGON2_TIME_COST);
    let argon2_memory_cost = opts
        .argon2_memory_cost
        .or(site_opts.memory_cost)
        .or(settings.memory_cost)
        .unwrap_or(DEFAULT_ARGON2_MEMORY_COST_KIB);
    let argon2_parallelism = opts
        .argon2_parallelism
        .or(site_opts.parallelism)
        .or(settings.parallelism)
        .unwrap_or(DEFAULT_ARGON2_PARALLELISM);
    let copy = resolve_flag(args.copy, args.no_copy, settings.copy, false);
    let use_digits = resolve_flag(
        opts.digits,
        opts.no_digits,
        site_opts.digits.or(settings.digits),
        true,
    );

    // CLIモード
    if length < MIN_PASSWORD_LENGTH {
        eprintln!(
            "エラー: パスワード長は{}文字以上を指定してください。",
            MIN_PASSWORD_LENGTH
        );
        std::process::exit(1);
    }

    // 記号セットを決める。-C/--char、サイトの登録内容、設定ファイルの char の
    // いずれかが指定された場合、デフォルトの記号セットを置き換える。
    let symbols: Vec<u8> = match (
        &opts.custom_symbols,
        &site_opts.custom_symbols,
        &settings.custom_symbols,
    ) {
        (Some(custom), _, _) => parse_custom_symbols(custom, "-C/--char"),
        (None, Some(custom), _) => parse_custom_symbols(custom, "サイトの登録内容の char"),
        (None, None, Some(custom)) => parse_custom_symbols(custom, "設定ファイルの char"),
        (None, None, None) => SYMBOLS.to_vec(),
    };

    // -C/--char をコマンドラインで指定した場合は、記号を使う意図とみなして常に有効にする
    let use_symbols = if opts.custom_symbols.is_some() {
        if opts.no_symbols {
            eprintln!("警告: --no-symbols が指定されていますが、-C/--char が指定されたため記号を使用します。");
        }
        true
    } else {
        resolve_flag(
            opts.symbols,
            opts.no_symbols,
            site_opts.symbols.or(settings.symbols),
            true,
        )
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
        if site.is_empty() { "(なし)" } else { &site },
        length,
        kdf,
        kdf_detail,
        use_digits,
        use_symbols,
    );

    let generate_opts = GenerateOptions {
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
    let password = generate_password(&core, &site, &seed, &generate_opts);
    let border = "-".repeat(password.len());
    eprintln!("{}", border);
    println!("{}", password);
    eprintln!("{}", border);

    if copy {
        clipboard::copy_to_clipboard(&password);
    }
}

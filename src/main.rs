mod cli;
mod clipboard;
mod config;
mod input;
mod kdf;
mod seed;
mod server;
#[cfg(windows)]
mod winacl;

use clap::Parser;

use cli::Args;
use config::MIN_PASSWORD_LENGTH;
use kdf::{generate_password, GenerateOptions, KdfAlgorithm, SYMBOLS};

fn main() {
    let args = Args::parse();

    let seed_path = config::seed_file_path();
    let seed = seed::load_or_create_seed(&seed_path);

    if args.server {
        let port = config::load_or_create_env();
        let html = config::load_html();
        server::run_server(port, seed, html);
        return;
    }

    // CLIモード
    if args.length < MIN_PASSWORD_LENGTH {
        eprintln!(
            "エラー: パスワード長は{}文字以上を指定してください。",
            MIN_PASSWORD_LENGTH
        );
        std::process::exit(1);
    }

    let core = input::prompt_masked(config::PROMPT_CORE_PASSWORD);
    if core.is_empty() {
        eprintln!("エラー: コアパスワードが空です。");
        std::process::exit(1);
    }

    let use_digits = !args.no_digits;
    let mut use_symbols = !args.no_symbols;

    // -C/--char が指定された場合、デフォルトの記号セットを置き換える
    let symbols: Vec<u8> = match &args.custom_symbols {
        Some(custom) => {
            if custom.is_empty() {
                eprintln!("エラー: -C/--char には1文字以上指定してください。");
                std::process::exit(1);
            }
            if !custom.is_ascii() {
                eprintln!("エラー: -C/--char はASCII文字のみ指定できます。");
                std::process::exit(1);
            }
            if args.no_symbols {
                eprintln!("警告: --no-symbols が指定されていますが、-C/--char が指定されたため記号を使用します。");
            }
            use_symbols = true;

            // 重複文字を除去する（入力順は保持）。重複があっても動作上問題はないが、
            // 同じ文字が複数枠を占めることによる分布の偏りを避けるため除去する。
            let mut seen = std::collections::HashSet::new();
            custom.bytes().filter(|b| seen.insert(*b)).collect()
        }
        None => SYMBOLS.to_vec(),
    };

    let kdf_detail = match args.kdf {
        KdfAlgorithm::Pbkdf2 => format!("iterations={}", args.iterations),
        KdfAlgorithm::Argon2id => format!(
            "time_cost={}, memory_cost={}KiB, parallelism={}",
            args.argon2_time_cost, args.argon2_memory_cost, args.argon2_parallelism
        ),
    };
    eprintln!(
        "生成中... (site={:?}, length={}, kdf={}, {}, digits={}, symbols={})",
        if args.site.is_empty() {
            "(なし)"
        } else {
            &args.site
        },
        args.length,
        args.kdf,
        kdf_detail,
        use_digits,
        use_symbols,
    );

    let opts = GenerateOptions {
        length: args.length,
        kdf: args.kdf,
        pbkdf2_iterations: args.iterations,
        argon2_time_cost: args.argon2_time_cost,
        argon2_memory_cost: args.argon2_memory_cost,
        argon2_parallelism: args.argon2_parallelism,
        use_digits,
        use_symbols,
        symbols: &symbols,
    };
    let password = generate_password(&core, &args.site, &seed, &opts);
    let border = "-".repeat(password.len());
    eprintln!("{}", border);
    println!("{}", password);
    eprintln!("{}", border);

    if args.copy {
        clipboard::copy_to_clipboard(&password);
    }
}

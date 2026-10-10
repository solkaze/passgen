use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{home_dir, seed_file_path, settings_file_path};
use crate::{seed, settings};

#[cfg(windows)]
const BIN_NAME: &str = "passgen.exe";
#[cfg(not(windows))]
const BIN_NAME: &str = "passgen";

fn install_dir() -> PathBuf {
    home_dir().join(".local").join("bin")
}

/// passgenを使える状態にする。何度実行しても既存のファイルは上書きしない。
///
/// 1. 現在実行中のバイナリを ~/.local/bin にコピーする
/// 2. 設定ファイルのテンプレートを ~/.config/passgen に作成する
/// 3. シードファイルを ~/.local/share/passgen に準備する（旧パスからの移行、または新規生成）
pub fn run_init() {
    println!("=== passgen 初期化 ===");

    let install_dir = install_dir();
    install_binary(&install_dir);
    init_settings();
    init_seed();
    print_path_hint(&install_dir);
}

fn install_binary(install_dir: &Path) {
    let current_exe = std::env::current_exe().expect("実行ファイルのパスを取得できません");
    let dest = install_dir.join(BIN_NAME);

    if is_same_file(&current_exe, &dest) {
        println!("バイナリ: インストール済みです ({})", dest.display());
        return;
    }

    if let Err(e) = fs::create_dir_all(install_dir) {
        eprintln!(
            "エラー: {} の作成に失敗しました: {}",
            install_dir.display(),
            e
        );
        std::process::exit(1);
    }

    if let Err(e) = fs::copy(&current_exe, &dest) {
        eprintln!("エラー: {} へのコピーに失敗しました: {}", dest.display(), e);
        std::process::exit(1);
    }

    println!("バイナリ: インストールしました ({})", dest.display());
}

fn init_settings() {
    let path = settings_file_path();
    match settings::create_template_if_missing(&path) {
        Ok(true) => println!("設定ファイル: 作成しました ({})", path.display()),
        Ok(false) => {
            // 既存の設定に誤りがあればここで気付けるよう、読み込めることを確認しておく
            settings::load(&path);
            println!("設定ファイル: 既に存在します ({})", path.display());
        }
        Err(e) => {
            eprintln!(
                "エラー: 設定ファイルの作成に失敗しました: {}: {}",
                path.display(),
                e
            );
            std::process::exit(1);
        }
    }
}

fn init_seed() {
    let path = seed_file_path();
    let existed = path.exists();
    // 旧パスからの移行・新規生成・パーミッション検査はシードの読み込み処理に任せる
    seed::load_or_create_seed(&path);
    if existed {
        println!("シードファイル: 既に存在します ({})", path.display());
    } else {
        println!("シードファイル: 準備しました ({})", path.display());
    }
}

fn is_same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn print_path_hint(install_dir: &Path) {
    let in_path = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p == install_dir))
        .unwrap_or(false);

    if !in_path {
        println!();
        println!("警告: {} はPATHに含まれていません。", install_dir.display());
        #[cfg(unix)]
        {
            println!("以下をシェルの設定ファイル（~/.bashrc, ~/.zshrc など）に追加してください:");
            println!("  export PATH=\"{}:$PATH\"", install_dir.display());
        }
        #[cfg(windows)]
        {
            println!("システム環境変数のPATHに次のディレクトリを追加してください:");
            println!("  {}", install_dir.display());
        }
    }

    println!();
    println!("使い方の例:");
    println!("  passgen add https://github.com/login   # サイトを登録する");
    println!("  passgen                                # 登録済みのサイトから選んで生成する");
    println!("  passgen -s github.com                  # サイト名を直接指定して生成する");
}

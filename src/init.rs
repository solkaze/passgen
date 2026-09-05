use std::fs;
use std::path::{Path, PathBuf};

use crate::config::home_dir;

#[cfg(windows)]
const BIN_NAME: &str = "passgen.exe";
#[cfg(not(windows))]
const BIN_NAME: &str = "passgen";

fn install_dir() -> PathBuf {
    home_dir().join(".local").join("bin")
}

/// 現在実行中のバイナリを ~/.local/bin にコピーし、PATH登録を促す。
pub fn run_init() {
    println!("=== passgen インストール ===");

    let current_exe = std::env::current_exe().expect("実行ファイルのパスを取得できません");
    let install_dir = install_dir();
    let dest = install_dir.join(BIN_NAME);

    if is_same_file(&current_exe, &dest) {
        println!("スキップ: 既にインストール済みです ({})", dest.display());
        print_path_hint(&install_dir);
        return;
    }

    if let Err(e) = fs::create_dir_all(&install_dir) {
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

    println!("インストール完了: {}", dest.display());
    print_path_hint(&install_dir);
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
    println!("CLI モード:      passgen -s github.com");
}

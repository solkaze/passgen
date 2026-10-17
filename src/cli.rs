use clap::builder::styling::{AnsiColor, Styles};
use clap::{Parser, Subcommand};

use crate::config::{
    DEFAULT_ARGON2_MEMORY_COST_KIB, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ITERATIONS, DEFAULT_LENGTH,
};
use crate::kdf::KdfAlgorithm;

// ============================================================
// ヘルプ表示のスタイル定義
// ============================================================

fn help_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Yellow.on_default().bold())
        .usage(AnsiColor::Yellow.on_default().bold())
        .literal(AnsiColor::Green.on_default().bold())
        .placeholder(AnsiColor::Cyan.on_default())
        .valid(AnsiColor::Green.on_default())
        .invalid(AnsiColor::Red.on_default().bold())
        .error(AnsiColor::Red.on_default().bold())
}

// ============================================================
// サブコマンドの定義
// ============================================================

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// passgenを~/.local/binにインストールし、設定ファイルとシードファイルを準備します
    Init,
}

// ============================================================
// CLIの定義
// ============================================================

// 値を取るオプションと真偽値のフラグは、省略時に設定ファイル
// （~/.config/passgen/settings.toml）の値を使う。指定の有無を区別できるよう
// Option で受け取り、デフォルト値の解決は呼び出し側で行う。
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, styles = help_styles())]
#[command(
    after_help = "省略したオプションは ~/.config/passgen/settings.toml の値が使われます（なければ上記のデフォルト）。"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// サイト名（URLをそのまま指定すると、ホスト名に揃えて使う）
    #[arg(short, long, default_value = "")]
    pub site: String,

    /// -s の文字列を正規化せず、そのまま使う
    #[arg(long)]
    pub raw: bool,

    #[arg(short, long, help = format!("生成するパスワードの長さ [デフォルト: {}]", DEFAULT_LENGTH))]
    pub length: Option<usize>,

    /// 鍵導出アルゴリズム [デフォルト: argon2id]
    #[arg(long = "kdf", value_enum)]
    pub kdf: Option<KdfAlgorithm>,

    #[arg(
        short,
        long,
        help = format!(
            "PBKDF2のイテレーション回数（--kdf pbkdf2 の場合のみ使用） [デフォルト: {}]",
            DEFAULT_ITERATIONS
        )
    )]
    pub iterations: Option<u32>,

    #[arg(
        long = "time-cost",
        help = format!(
            "Argon2idのタイムコスト（--kdf argon2id の場合のみ使用） [デフォルト: {}]",
            DEFAULT_ARGON2_TIME_COST
        )
    )]
    pub argon2_time_cost: Option<u32>,

    #[arg(
        long = "memory-cost",
        help = format!(
            "Argon2idのメモリコスト、KiB単位（--kdf argon2id の場合のみ使用） [デフォルト: {}]",
            DEFAULT_ARGON2_MEMORY_COST_KIB
        )
    )]
    pub argon2_memory_cost: Option<u32>,

    #[arg(
        long = "parallelism",
        help = format!(
            "Argon2idの並列度（--kdf argon2id の場合のみ使用） [デフォルト: {}]",
            DEFAULT_ARGON2_PARALLELISM
        )
    )]
    pub argon2_parallelism: Option<u32>,

    /// 生成したパスワードをクリップボードにコピーする
    #[arg(short, long)]
    pub copy: bool,

    /// クリップボードにコピーしない（設定ファイルの copy = true を打ち消す）
    #[arg(long = "no-copy", conflicts_with = "copy")]
    pub no_copy: bool,

    /// 数字を含める（設定ファイルの digits = false を打ち消す）
    #[arg(long = "digits", conflicts_with = "no_digits")]
    pub digits: bool,

    /// 数字を含めない
    #[arg(long = "no-digits")]
    pub no_digits: bool,

    /// 記号を含める（設定ファイルの symbols = false を打ち消す）
    #[arg(long = "symbols", conflicts_with = "no_symbols")]
    pub symbols: bool,

    /// 記号を含めない
    #[arg(long = "no-symbols")]
    pub no_symbols: bool,

    /// 使用可能な記号を指定する
    #[arg(short = 'C', long = "char")]
    pub custom_symbols: Option<String>,
}

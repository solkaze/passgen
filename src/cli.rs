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
    /// サイトを登録します（URLをそのまま指定できます）
    Add(AddArgs),
    /// 登録済みのサイトを一覧表示します
    List,
    /// 登録済みのサイトを削除します
    Remove {
        /// 削除するサイトの登録名
        name: String,
    },
}

#[derive(clap::Args, Debug)]
pub struct AddArgs {
    /// 登録するサイトのURLまたはホスト名
    pub site: String,

    /// 生成時に指定する登録名（省略時は正規化後のサイト名）
    #[arg(short, long)]
    pub name: Option<String>,

    /// サイト名を正規化せず、指定した文字列をそのまま登録する
    #[arg(long)]
    pub raw: bool,

    // ここで指定した値はサイトの登録内容として保存され、生成のたびに適用される
    #[command(flatten)]
    pub options: GenArgs,
}

// ============================================================
// 生成条件のオプション
// ============================================================

// 生成時の指定と、サイト登録時（add）の指定で共通して使う。
// 値を取るオプションと真偽値のフラグは、省略時にサイトの登録内容や設定ファイル
// （~/.config/passgen/settings.toml）の値を使う。指定の有無を区別できるよう
// Option で受け取り、デフォルト値の解決は呼び出し側で行う。
#[derive(clap::Args, Debug)]
pub struct GenArgs {
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

// ============================================================
// CLIの定義
// ============================================================

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, styles = help_styles())]
#[command(
    after_help = "省略したオプションは、サイトの登録内容、~/.config/passgen/settings.toml の順で値が使われます（なければ上記のデフォルト）。"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// サイトの登録名、URL、またはホスト名（省略時は登録済みのサイトから選択）
    #[arg(short, long)]
    pub site: Option<String>,

    /// -s の文字列を正規化せず、登録内容も参照せずにそのまま使う
    #[arg(long, requires = "site")]
    pub raw: bool,

    #[command(flatten)]
    pub options: GenArgs,

    /// 生成したパスワードをクリップボードにコピーする
    #[arg(short, long)]
    pub copy: bool,

    /// クリップボードにコピーしない（設定ファイルの copy = true を打ち消す）
    #[arg(long = "no-copy", conflicts_with = "copy")]
    pub no_copy: bool,
}

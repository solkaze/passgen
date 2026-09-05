use clap::builder::styling::{AnsiColor, Styles};
use clap::Parser;

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
// CLIの定義
// ============================================================

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, styles = help_styles())]
pub struct Args {
    /// サイト名
    #[arg(short, long, default_value = "")]
    pub site: String,

    /// 生成するパスワードの長さ
    #[arg(short, long, default_value_t = DEFAULT_LENGTH)]
    pub length: usize,

    /// 鍵導出アルゴリズム
    #[arg(long = "kdf", value_enum, default_value = "argon2id")]
    pub kdf: KdfAlgorithm,

    /// PBKDF2のイテレーション回数（--kdf pbkdf2 の場合のみ使用）
    #[arg(short, long, default_value_t = DEFAULT_ITERATIONS)]
    pub iterations: u32,

    /// Argon2idのタイムコスト（--kdf argon2id の場合のみ使用）
    #[arg(long = "time-cost", default_value_t = DEFAULT_ARGON2_TIME_COST)]
    pub argon2_time_cost: u32,

    /// Argon2idのメモリコスト、KiB単位（--kdf argon2id の場合のみ使用）
    #[arg(long = "memory-cost", default_value_t = DEFAULT_ARGON2_MEMORY_COST_KIB)]
    pub argon2_memory_cost: u32,

    /// Argon2idの並列度（--kdf argon2id の場合のみ使用）
    #[arg(long = "parallelism", default_value_t = DEFAULT_ARGON2_PARALLELISM)]
    pub argon2_parallelism: u32,

    /// 生成したパスワードをクリップボードにコピーする
    #[arg(short, long)]
    pub copy: bool,

    /// ブラウザUIモードで起動する
    #[arg(short = 'S', long = "server")]
    pub server: bool,

    /// 数字を含めない
    #[arg(long = "no-digits")]
    pub no_digits: bool,

    /// 記号を含めない
    #[arg(long = "no-symbols")]
    pub no_symbols: bool,

    /// 使用可能な記号を指定する
    #[arg(short = 'C', long = "char")]
    pub custom_symbols: Option<String>,
}

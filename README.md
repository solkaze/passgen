# passgen

コアパスワードとサイト名から、決定論的にパスワードを生成する Rust 製のパスワードジェネレータです。
生成されたパスワードはどこにも保存されません。同じ入力からは常に同じパスワードが再現されるため、保管の必要がありません。

- **決定論的生成**: `コアパスワード + サイト名 + 端末ごとのシード` から Argon2id（デフォルト）または PBKDF2-HMAC-SHA256（互換用）で導出
- **保存ゼロ**: 生成結果は一切保存されず、必要なときに再生成する
- **シンプルな CLI**: 対話プロンプトでコアパスワードを入力するだけのコマンド 1 つ
- **クロスプラットフォーム**: Linux / macOS / Windows / WSL2 に対応

---

## 仕組み

パスワードは次の流れで導出されます。

```
seed (512 bytes, 端末ごとに生成) ───┐
                                 ├─► Argon2id / PBKDF2-HMAC-SHA256 ─► bytes ─► 文字列化 ─► パスワード
core password (ユーザー入力)   ────┤   (--kdf で選択、デフォルトは Argon2id)
                                 │
site + ":passgen" (salt) ────────┘
```

- **seed**: 初回起動時に `~/.local/share/passgen/passgen_seed` に自動生成される 512 バイト（4096bit）のランダム値。SSH 秘密鍵などと同様に、`BEGIN/END PASSGEN PRIVATE SEED` で囲んだPEM風のテキストとして保存され、Unix ではパーミッション `0400`（ディレクトリは `0700`）で保存されます（グループ・その他に権限が付いている場合は実行を中止します）。Windows では NTFS の ACL を検査し、所有者・Administrators・SYSTEM 以外のアカウントがアクセスできる状態であれば実行を中止します。この値が同じコアパスワード・サイト名でも端末ごとに異なる結果を出すためのキーになります。**内容を表示・共有・コミットしてはいけません。**
- **鍵導出アルゴリズム**: デフォルトは Argon2id（メモリハードで GPU/ASIC 総当たりに強い）。`--kdf pbkdf2` を指定すると、旧バージョン（PBKDF2-HMAC-SHA256、600,000 回）で生成したパスワードを再現できます。
  - Argon2id のデフォルトコスト: タイムコスト `3`、メモリコスト `65536 KiB`（64 MiB）、並列度 `4`。`--time-cost` / `--memory-cost` / `--parallelism` で変更できます。
  - PBKDF2 のデフォルトイテレーション: `600,000` 回。`-i/--iterations` で変更できます。
- **文字種の保証**: 数字・記号を使う設定のときに、万一導出バイトの出力にそれらが含まれなかった場合でも、導出バイトから決定論的に位置と文字を選んで差し替えます。こちらも再現性が保たれます。

同じ `seed + core + site + length + kdf + コストパラメータ + 文字種フラグ + 記号セット` であれば、常に同じパスワードが生成されます。**`--kdf` やコストパラメータを変更すると、同じサイト・コアパスワードでも別のパスワードになります。**

---

## 必要なもの

- Rust ツールチェーン（`rustc` / `cargo`、stable）。インストールは [rustup](https://rustup.rs/) を推奨。
- クリップボードコピー機能（`-c`）を使う場合、プラットフォームごとに以下が必要:
  - **Linux (Wayland)**: `wl-copy`
  - **Linux (X11)**: `xclip` または `xsel`
  - **WSL2**: `clip.exe`（Windows 側に標準搭載）
  - **Windows**: 追加依存なし
  - **macOS**: 現状は `pbcopy` に未対応のため、`xclip` / `xsel` などを別途用意する必要があります

---

## インストール

### バイナリをダウンロードする場合

[Releases](https://github.com/solkaze/passgen/releases) から OS に合ったアーカイブをダウンロードし、展開してください。

```sh
passgen init
```

`passgen init` を実行すると、次の準備を行います。何度実行しても既存のファイルは上書きされません。

1. 実行中のバイナリを `~/.local/bin/passgen` にコピーする（`~/.local/bin` が PATH に含まれていない場合は、追加方法が案内されます）
2. 設定ファイルのテンプレートを `~/.config/passgen/settings.toml` に作成する
3. シードファイルを `~/.local/share/passgen/passgen_seed` に準備する（旧パスにある場合は移行、なければ新規生成）

別端末のシードを引き継ぐ場合は、`passgen init` の前にシードファイルをコピーしておいてください（[別端末で同じパスワードを再現したい場合](#別端末で同じパスワードを再現したい場合)を参照）。

### ソースからビルドする場合

```sh
git clone https://github.com/solkaze/passgen.git
cd passgen
cargo build --release
./target/release/passgen init
```

`cargo build --release` の後に `passgen init` を実行すると、`target/release/passgen` が `~/.local/bin/passgen` にコピーされ、設定ファイルとシードファイルが準備されます。ソースを更新して再ビルドした場合は、`passgen init` を再実行してコピーを更新してください。

---

## 使い方

### 基本的な使い方

```sh
passgen -s github.com
```

プロンプトでコアパスワードを入力すると、パスワードが標準出力に表示されます。コアパスワードの入力はターミナル上でマスク（`*`）表示されます。

#### 主なオプション

| オプション | 説明 | デフォルト |
|---|---|---|
| `-s, --site <NAME>` | サイト名（salt の元になる） | `""` |
| `-l, --length <N>` | 生成するパスワードの長さ（8 以上） | `64` |
| `--kdf <pbkdf2\|argon2id>` | 鍵導出アルゴリズム | `argon2id` |
| `-i, --iterations <N>` | PBKDF2 のイテレーション回数（`--kdf pbkdf2` の場合のみ） | `600000` |
| `--time-cost <N>` | Argon2id のタイムコスト（`--kdf argon2id` の場合のみ） | `3` |
| `--memory-cost <KiB>` | Argon2id のメモリコスト（`--kdf argon2id` の場合のみ） | `65536` |
| `--parallelism <N>` | Argon2id の並列度（`--kdf argon2id` の場合のみ） | `4` |
| `-c, --copy` | 生成結果をクリップボードにコピー | off |
| `--no-copy` | クリップボードにコピーしない（設定ファイルの `copy = true` を打ち消す） | off |
| `--no-digits` | 数字を含めない | off |
| `--digits` | 数字を含める（設定ファイルの `digits = false` を打ち消す） | off |
| `--no-symbols` | 記号を含めない | off |
| `--symbols` | 記号を含める（設定ファイルの `symbols = false` を打ち消す） | off |
| `-C, --char <CHARS>` | 記号として使用する文字を指定する（デフォルトの記号セットを置き換える） | `!@#$%^&*()-_=+[]{}\|;:,.<>?` |

`-C/--char` は ASCII 文字を 1 文字以上指定してください（重複文字は自動的に除去されます）。`--no-symbols` と同時に指定した場合は警告を表示したうえで `-C/--char` が優先され、記号が使用されます。

#### 使用例

```sh
# クリップボードにコピー（対応ツールが必要）
passgen -s github.com -c

# 長さ 32・記号なし
passgen -s example.com -l 32 --no-symbols

# 使用できる記号が限られているサイト向けに、記号セットを指定する
passgen -s example.com -C '!@#-_'

# 旧バージョン（PBKDF2）で生成したパスワードを再現する
passgen -s bank.example.com --kdf pbkdf2 -i 1000000

# Argon2id のコストを上げる
passgen -s bank.example.com --time-cost 5 --memory-cost 131072
```

---

## 設定ファイル

毎回同じオプションを指定する場合は、`~/.config/passgen/settings.toml` に書いておくと省略できます。`passgen init` を実行すると、全項目をコメントアウトしたテンプレートが作成されます。

```toml
length = 32
kdf = "argon2id"
time_cost = 5
memory_cost = 131072
copy = true
char = "!@#-_"
```

| キー | 対応するオプション | 型 |
|---|---|---|
| `length` | `-l, --length` | 整数 |
| `kdf` | `--kdf` | `"argon2id"` または `"pbkdf2"` |
| `iterations` | `-i, --iterations` | 整数 |
| `time_cost` | `--time-cost` | 整数 |
| `memory_cost` | `--memory-cost` | 整数（KiB） |
| `parallelism` | `--parallelism` | 整数 |
| `copy` | `-c, --copy` / `--no-copy` | 真偽値 |
| `digits` | `--digits` / `--no-digits` | 真偽値 |
| `symbols` | `--symbols` / `--no-symbols` | 真偽値 |
| `char` | `-C, --char` | 文字列 |

- 値は **コマンドラインオプション > 設定ファイル > 組み込みのデフォルト** の順で決まります。サイト名（`-s`）は設定ファイルには書けません。
- すべてのキーは省略できます。未知のキーや型の合わない値がある場合は、エラーを表示して実行を中止します（打ち間違いに気付かないまま別のパスワードが生成されるのを防ぐためです）。
- `symbols = false` のときは `char` を書いていても記号は使われません。コマンドラインで `-C/--char` を指定した場合は、設定ファイルの `symbols` にかかわらず記号が使われます。
- **`copy` 以外の値を変えると、同じサイト名・コアパスワードでも生成されるパスワードが変わります。** 実際に使われた値は、生成時に表示される `生成中... (...)` の行で確認できます。

---

## ファイルとディレクトリ

| パス | 内容 |
|---|---|
| `~/.config/passgen/settings.toml` | 設定ファイル。自由に編集でき、dotfiles などで管理しても問題ありません。|
| `~/.local/share/passgen/passgen_seed` | 端末ごとのシード（512 バイト、PEM風テキスト、`0400`）。秘密鍵と同様に扱ってください。|

シードは失うと復元できず、公開もできないファイルです。編集・削除・dotfiles 管理の対象になりやすい設定ディレクトリに置くと誤操作や誤コミットの原因になるため、設定ファイルとは別のディレクトリに置いています。

旧バージョンでは `~/.config/passgen/passgen_seed`（さらに古いバージョンでは `~/.pass-gen-seed`）に生成していましたが、初回起動時または `passgen init` の実行時に自動で新しいパスへ移行されます。

### 別端末で同じパスワードを再現したい場合

同じ結果を出すには `~/.local/share/passgen/passgen_seed` を移行先にコピーしてください。パーミッションは所有者のみがアクセスできる状態（`0400`）を保ってください。設定ファイルで値を変更している場合は、`~/.config/passgen/settings.toml` も合わせてコピーしてください。

```sh
# 安全な経路で転送する（例: scp）
ssh user@other-host 'mkdir -p ~/.local/share/passgen && chmod 700 ~/.local/share/passgen'
scp ~/.local/share/passgen/passgen_seed user@other-host:~/.local/share/passgen/passgen_seed
ssh user@other-host 'chmod 400 ~/.local/share/passgen/passgen_seed'
```

移行先で既にシードが生成されている場合は、読み取り専用のため上書きできません。移行先のシードが不要であることを確認したうえで、削除してからコピーしてください。

シードが異なれば、同じコアパスワード・サイト名でも別のパスワードになります。

---

## セキュリティに関する注意

- **コアパスワードは誰にも教えず、どこにも保存しないでください。** このツールが守っているのは「生成結果を保存しない」ことだけです。コアパスワードの強度がそのままパスワードの強度になります。
- **`~/.local/share/passgen/passgen_seed` のバックアップ**を取ってください。このファイルを失うと、同じコアパスワードを入れても以前と同じパスワードは再現できなくなります。SSH 秘密鍵と同様、このファイルの内容を表示・共有・コミットしないでください。
- **設定ファイルで値を変更している場合は、その内容も控えておいてください。** 長さや KDF のパラメータが変わると、同じシード・コアパスワードでも以前と同じパスワードは再現できません。

---

## テスト

```sh
cargo test
```

決定性・長さ・文字種保証・サイトごとの差分・シードごとの差分などを確認するテストが含まれています。

---

## ライセンス
MIT

# pass-gen

コアパスワードとサイト名から、決定論的にパスワードを生成する Rust 製のパスワードジェネレータです。
生成されたパスワードはどこにも保存されません。同じ入力からは常に同じパスワードが再現されるため、保管の必要がありません。

- **決定論的生成**: `コアパスワード + サイト名 + 端末ごとのシード` から Argon2id（デフォルト）または PBKDF2-HMAC-SHA256（互換用）で導出
- **保存ゼロ**: 生成結果は一切保存されず、必要なときに再生成する
- **2 つのモード**: ターミナルで完結する CLI モードと、ブラウザ UI で使うサーバーモード
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

- **seed**: 初回起動時に `~/.config/passgen/passgen_seed` に自動生成される 512 バイト（4096bit）のランダム値。SSH 秘密鍵などと同様に、`BEGIN/END PASSGEN PRIVATE SEED` で囲んだPEM風のテキストとして保存され、Unix ではパーミッション `0600` で保存されます（パーミッションが異なる場合は実行を中止します）。この値が同じコアパスワード・サイト名でも端末ごとに異なる結果を出すためのキーになります。**内容を表示・共有・コミットしてはいけません。**
- **鍵導出アルゴリズム**: デフォルトは Argon2id（メモリハードで GPU/ASIC 総当たりに強い）。`--kdf pbkdf2` を指定すると、旧バージョン（PBKDF2-HMAC-SHA256、600,000 回）で生成したパスワードを再現できます。
  - Argon2id のデフォルトコスト: タイムコスト `3`、メモリコスト `65536 KiB`（64 MiB）、並列度 `4`。`--time-cost` / `--memory-cost` / `--parallelism` で変更できます。
  - PBKDF2 のデフォルトイテレーション: `600,000` 回。`-i/--iterations` で変更できます。
- **文字種の保証**: 数字・記号を使う設定のときに、万一導出バイトの出力にそれらが含まれなかった場合でも、導出バイトから決定論的に位置と文字を選んで差し替えます。こちらも再現性が保たれます。

同じ `seed + core + site + length + kdf + コストパラメータ + 文字種フラグ` であれば、常に同じパスワードが生成されます。**`--kdf` やコストパラメータを変更すると、同じサイト・コアパスワードでも別のパスワードになります。**

---

## 必要なもの

- Rust ツールチェーン（`rustc` / `cargo`、stable）。インストールは [rustup](https://rustup.rs/) を推奨。
- クリップボードコピー機能（`-c`）を使う場合、プラットフォームごとに以下が必要:
  - **Linux (Wayland)**: `wl-copy`
  - **Linux (X11)**: `xclip` または `xsel`
  - **WSL2**: `clip.exe`（Windows 側に標準搭載）
  - **macOS / Windows**: 追加依存なし

---

## インストール

### バイナリをダウンロードする場合

[Releases](https://github.com/<your-account>/pass-gen/releases) から OS に合ったアーカイブをダウンロードし、展開してください。

```sh
passgen init
```

`passgen init` を実行すると、実行中のバイナリを `~/.local/bin/passgen` にコピーします。`~/.local/bin` が PATH に含まれていない場合は、追加方法が案内されます。

### ソースからビルドする場合

```sh
git clone https://github.com/<your-account>/pass-gen.git
cd pass-gen
cargo build --release
./target/release/passgen init
```

`cargo build --release` の後に `passgen init` を実行すると、`target/release/passgen` が `~/.local/bin/passgen` にコピーされます。ソースを更新して再ビルドした場合は、`passgen init` を再実行してコピーを更新してください。

> **サーバーモード（`-S`）について**: `.env` と `html/index.html` は実行ファイルのパスから 2 階層上（プロジェクトルート）を基準に解決されるため、`passgen init` でコピーした後は正しく動作しません。サーバーモードを使う場合は、プロジェクトディレクトリ内の `target/release/passgen` を直接実行してください。

---

## 使い方

### CLI モード

```sh
pass-gen -s github.com
```

プロンプトでコアパスワードを入力すると、パスワードが標準出力に表示されます。コアパスワードの入力はターミナル上でマスク（`*`）表示されます。

#### 主なオプション

| オプション | 説明 | デフォルト |
|---|---|---|
| `-s, --site <NAME>` | サイト名（salt の元になる） | `""` |
| `-l, --length <N>` | 生成するパスワードの長さ（8 以上） | `48` |
| `--kdf <pbkdf2\|argon2id>` | 鍵導出アルゴリズム | `argon2id` |
| `-i, --iterations <N>` | PBKDF2 のイテレーション回数（`--kdf pbkdf2` の場合のみ） | `600000` |
| `--time-cost <N>` | Argon2id のタイムコスト（`--kdf argon2id` の場合のみ） | `3` |
| `--memory-cost <KiB>` | Argon2id のメモリコスト（`--kdf argon2id` の場合のみ） | `65536` |
| `--parallelism <N>` | Argon2id の並列度（`--kdf argon2id` の場合のみ） | `4` |
| `-c, --copy` | 生成結果をクリップボードにコピー | off |
| `-S, --server` | ブラウザ UI モードで起動 | off |
| `--no-digits` | 数字を含めない | off |
| `--no-symbols` | 記号を含めない | off |

#### 使用例

```sh
# クリップボードにコピー（対応ツールが必要）
pass-gen -s github.com -c

# 長さ 32・記号なし
pass-gen -s example.com -l 32 --no-symbols

# 旧バージョン（PBKDF2）で生成したパスワードを再現する
pass-gen -s bank.example.com --kdf pbkdf2 -i 1000000

# Argon2id のコストを上げる
pass-gen -s bank.example.com --time-cost 5 --memory-cost 131072
```

### サーバーモード（ブラウザ UI）

```sh
pass-gen -S
```

`127.0.0.1:11010`（デフォルト）で待ち受け、ローカルブラウザを自動で開きます。WSL2 環境では `cmd.exe /c start` 経由で Windows 側のブラウザが開きます。

ブラウザ上からサイト名・コアパスワード・長さ・鍵導出アルゴリズム（Argon2id / PBKDF2）とそのコストパラメータ・文字種を指定してパスワードを生成できます。UI 右上の終了ボタン、またはウィンドウを閉じるとサーバーも停止します。

ポート番号はプロジェクトルートの `.env` の `PORT` で変更できます。

```
PORT=11010
```

---

## ファイルとディレクトリ

| パス | 内容 |
|---|---|
| `~/.config/passgen/passgen_seed` | 端末ごとのシード（512 バイト、PEM風テキスト、`0600`）。秘密鍵と同様に扱ってください。|
| `<project>/.env` | サーバーモードの設定（ポート番号）。初回起動時に自動生成。|
| `<project>/html/index.html` | サーバーモードで配信される UI。|

旧バージョンでは `~/.pass-gen-seed` に生成していましたが、初回起動時に自動で新しいパスへ移行されます。

### 別端末で同じパスワードを再現したい場合

同じ結果を出すには `~/.config/passgen/passgen_seed` を移行先にコピーしてください。パーミッションは `0600` を保ってください。

```sh
# 安全な経路で転送する（例: scp）
scp ~/.config/passgen/passgen_seed user@other-host:~/.config/passgen/passgen_seed
ssh user@other-host 'chmod 600 ~/.config/passgen/passgen_seed'
```

シードが異なれば、同じコアパスワード・サイト名でも別のパスワードになります。

---

## セキュリティに関する注意

- **コアパスワードは誰にも教えず、どこにも保存しないでください。** このツールが守っているのは「生成結果を保存しない」ことだけです。コアパスワードの強度がそのままパスワードの強度になります。
- **`~/.config/passgen/passgen_seed` のバックアップ**を取ってください。このファイルを失うと、同じコアパスワードを入れても以前と同じパスワードは再現できなくなります。SSH 秘密鍵と同様、このファイルの内容を表示・共有・コミットしないでください。
- 同梱の JSON パーサは非常に単純な実装で、**ローカル（127.0.0.1）専用**の用途を想定しています。外部に公開しないでください。

---

## テスト

```sh
cargo test
```

決定性・長さ・文字種保証・サイトごとの差分・シードごとの差分・HTTP ハンドラのパースなどを確認するテストが含まれています。

---

## ライセンス
MIT

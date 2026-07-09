#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "=== passgen 初期セットアップ ==="

# .env の作成（プロジェクトルートに配置）
if [ ! -f "$ENV_FILE" ]; then
    cat >"$ENV_FILE" <<'ENVEOF'
# passgen 設定ファイル
# サーバーのポート番号
PORT=11010
ENVEOF
    echo "作成: $ENV_FILE"
else
    echo "スキップ: $ENV_FILE は既に存在します"
fi

# ビルド
echo ""
echo "ビルド中..."
cd "$SCRIPT_DIR"
cargo build --release

# シンボリックリンクの作成
if [ ! -L $HOME/.local/bin/pass-gen ]; then
    sudo ln -s "$SCRIPT_DIR/target/release/passgen" $HOME/.local/bin/passgen
    echo "シンボリックリンク作成: $HOME/.local/bin/passgen → $SCRIPT_DIR/target/release/passgen"
else
    echo "スキップ: $HOME/.local/bin/passgen は既に存在します"
fi

echo ""
echo "=== セットアップ完了 ==="
echo "CLI モード:      passgen -s github.com"
echo "ブラウザモード:  passgen -S"

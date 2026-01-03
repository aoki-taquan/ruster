# 開発環境構築手順

Ubuntu 24.04 LTS での環境構築手順。

## 必要なもの

| ツール | 用途 |
|--------|------|
| Docker | コンテナランタイム（Containerlabの前提） |
| Containerlab | ネットワークテスト環境 |
| Rust/Cargo | ビルド |

## 1. Docker インストール

```bash
# 前提パッケージ
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

# Docker GPG キー追加
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# リポジトリ追加
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" | sudo tee /etc/apt/sources.list.d/docker.list

# インストール
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# ユーザーをdockerグループに追加（再ログイン必要）
sudo usermod -aG docker $USER
```

## 2. Containerlab インストール

```bash
bash -c "$(curl -sL https://get.containerlab.dev)"

# clabグループに追加（オプション）
sudo usermod -aG clab_admins $USER
```

## 3. Rust インストール

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# パス反映
source ~/.cargo/env
```

## 4. 確認

```bash
docker --version        # Docker version 29.x.x
containerlab version    # containerlab 0.7x.x
rustc --version         # rustc 1.9x.x
cargo --version         # cargo 1.9x.x
```

## 5. ビルド

```bash
cd /home/aoki/ruster
cargo build
```

## 6. テスト実行（要root）

```bash
sudo containerlab deploy -t test.clab.yml
```

## 注意事項

- `sudo usermod -aG docker $USER` 後は再ログインが必要
- rusterの実行にはroot権限必要（AF_PACKET使用のため）
- Containerlabもroot権限で実行

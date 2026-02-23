# Self-Hosted Runner Setup Guide

self-hosted runner で KVM/VM 系の統合テスト (containerlab E2E) を実行するためのセットアップ手順。

GitHub-hosted runner では KVM アクセスが制限されるため、VM kind を含むトポロジテストには self-hosted runner が必要。

---

## 1. ハードウェア・OS 要件

| 項目 | 要件 |
|------|------|
| アーキテクチャ | x86_64 (AMD64) |
| OS | Ubuntu 22.04 LTS / 24.04 LTS (推奨) |
| CPU | 4 コア以上 |
| メモリ | 8 GB 以上 |
| ディスク | 50 GB 以上の空き容量 |
| KVM | `/dev/kvm` が利用可能であること |
| ネットワーク | GitHub への HTTPS アウトバウンド接続 |

### KVM サポートの確認

```bash
# KVM モジュールが読み込まれているか確認
lsmod | grep kvm

# /dev/kvm が存在するか確認
ls -la /dev/kvm

# KVM が利用可能か確認 (kvm-ok)
sudo apt install -y cpu-checker
kvm-ok
```

---

## 2. 必須ソフトウェアのインストール

### 2.1 Docker

```bash
# Docker 公式リポジトリをセットアップ
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# runner ユーザを docker グループに追加
sudo usermod -aG docker $USER
```

### 2.2 containerlab

```bash
# containerlab v0.44+ をインストール
bash -c "$(curl -sL https://get.containerlab.dev)"

# バージョン確認
containerlab version
```

### 2.3 Rust ツールチェイン

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup default stable
```

### 2.4 追加ツール

```bash
sudo apt install -y \
  git \
  build-essential \
  pkg-config \
  iproute2 \
  iputils-ping \
  traceroute \
  jq
```

---

## 3. GitHub Actions Runner のインストール

### 3.1 runner ユーザの作成

```bash
sudo useradd -m -s /bin/bash github-runner
sudo usermod -aG docker github-runner
sudo usermod -aG kvm github-runner
```

### 3.2 runner のダウンロードと設定

GitHub リポジトリの Settings > Actions > Runners > New self-hosted runner から最新の手順を確認する。

```bash
sudo su - github-runner

# runner ディレクトリ
mkdir -p ~/actions-runner && cd ~/actions-runner

# 最新の runner パッケージをダウンロード (バージョンは GitHub の手順を参照)
curl -o actions-runner-linux-x64.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz
tar xzf actions-runner-linux-x64.tar.gz

# runner を設定 (TOKEN はリポジトリ設定画面から取得)
./config.sh --url https://github.com/<OWNER>/ruster \
  --token <REGISTRATION_TOKEN> \
  --labels self-hosted,linux,kvm \
  --name ruster-e2e-runner \
  --work _work
```

### 3.3 ラベル設定

runner には以下のラベルを付与する:

| ラベル | 用途 |
|--------|------|
| `self-hosted` | self-hosted runner の識別 (自動付与) |
| `linux` | OS 識別 (自動付与) |
| `kvm` | KVM 利用可能を示すカスタムラベル |

### 3.4 サービスとして登録

```bash
# runner ディレクトリで実行
sudo ./svc.sh install github-runner
sudo ./svc.sh start

# ステータス確認
sudo ./svc.sh status
```

---

## 4. ネットワーク構成

### 4.1 GitHub への接続

runner は以下のエンドポイントに HTTPS (443) でアウトバウンド接続する:

- `github.com`
- `api.github.com`
- `*.actions.githubusercontent.com`
- `ghcr.io` (コンテナイメージ)
- `*.blob.core.windows.net` (runner パッケージ)

### 4.2 containerlab ネットワーク

containerlab はホスト上に veth ペアとブリッジを作成する。テスト用のサブネット (`192.168.1.0/24`, `10.0.0.0/24`) がホストの実ネットワークと競合しないことを確認する。

競合する場合は `tests/containerlab/topology.yml` のアドレス割り当てを変更する。

### 4.3 Docker ネットワーク

Docker のデフォルトブリッジ (`172.17.0.0/16`) と containerlab が使用するネットワークが競合しないことを確認する。

---

## 5. セキュリティ考慮事項

### 5.1 runner のスコープ

- runner はリポジトリスコープで登録する (Organization スコープは使わない)
- public リポジトリでは self-hosted runner を使用しない (任意のコード実行リスク)

### 5.2 権限の最小化

- runner ユーザは `docker` グループと `kvm` グループのみに所属させる
- `sudo` 権限は containerlab の deploy/destroy に必要な範囲に限定する

```bash
# /etc/sudoers.d/github-runner
github-runner ALL=(root) NOPASSWD: /usr/bin/containerlab
github-runner ALL=(root) NOPASSWD: /usr/sbin/ip
github-runner ALL=(root) NOPASSWD: /usr/sbin/sysctl
```

### 5.3 ワークディレクトリのクリーンアップ

ジョブ終了後にワークディレクトリが自動クリーンアップされるよう、runner の設定で確認する。

### 5.4 シークレットの管理

- runner マシンに保存するシークレットは最小限にする
- GitHub Actions のシークレット機能を使用し、ワークフロー内でのみ参照する

---

## 6. 失敗時のログ収集

### 6.1 自動ログ収集 (CI)

`integration-test.yml` ワークフローでは、テスト失敗時に以下を自動的に収集する:

- 各コンテナ (`ruster`, `lan-host`, `wan-host`) の Docker ログ
- `docker ps -a` の出力
- ホストのネットワークインタフェース一覧
- containerlab の inspect 出力

収集されたログは GitHub Actions の Artifacts (`e2e-logs`) として 7 日間保持される。

### 6.2 手動ログ収集

テスト失敗を手動で調査する場合:

```bash
# コンテナログ
for node in ruster lan-host wan-host; do
  echo "=== clab-ruster-e2e-${node} ==="
  docker logs clab-ruster-e2e-${node} 2>&1
done

# containerlab のトポロジ状態
sudo containerlab inspect --topo tests/containerlab/topology.yml

# 各ノードのネットワーク状態
for node in ruster lan-host wan-host; do
  echo "=== ${node}: interfaces ==="
  docker exec clab-ruster-e2e-${node} ip addr show
  echo "=== ${node}: routes ==="
  docker exec clab-ruster-e2e-${node} ip route show
  echo "=== ${node}: arp ==="
  docker exec clab-ruster-e2e-${node} ip neigh show
done
```

### 6.3 ログの保存先

手動収集時は `/tmp/ruster-e2e-logs/` に保存する:

```bash
LOG_DIR=/tmp/ruster-e2e-logs
mkdir -p "$LOG_DIR"

for node in ruster lan-host wan-host; do
  docker logs clab-ruster-e2e-${node} > "${LOG_DIR}/${node}.log" 2>&1
done

sudo containerlab inspect --topo tests/containerlab/topology.yml > "${LOG_DIR}/topology-inspect.txt" 2>&1
docker ps -a > "${LOG_DIR}/docker-ps.txt" 2>&1
ip link show > "${LOG_DIR}/host-interfaces.txt" 2>&1
```

---

## 7. トラブルシューティング

### runner が GitHub に接続できない

```bash
# DNS 解決を確認
nslookup github.com

# HTTPS 接続を確認
curl -sI https://github.com

# runner のログを確認
journalctl -u actions.runner.*.service -n 50
```

### runner がオフラインと表示される

```bash
# サービスの状態を確認
sudo ./svc.sh status

# サービスを再起動
sudo ./svc.sh stop
sudo ./svc.sh start
```

### Docker 権限エラー

```bash
# runner ユーザが docker グループに所属しているか確認
groups github-runner

# Docker ソケットの権限を確認
ls -la /var/run/docker.sock

# グループ変更後はサービスを再起動
sudo ./svc.sh stop
sudo ./svc.sh start
```

### containerlab deploy が失敗する

```bash
# Docker が起動しているか
sudo systemctl status docker

# 前回のトポロジが残っている場合
sudo containerlab destroy --topo tests/containerlab/topology.yml --cleanup

# containerlab のバージョン確認
containerlab version
```

### KVM が利用できない

```bash
# BIOS で VT-x / AMD-V が有効か確認
dmesg | grep -i kvm

# カーネルモジュールをロード
sudo modprobe kvm
sudo modprobe kvm_intel  # Intel CPU の場合
sudo modprobe kvm_amd    # AMD CPU の場合

# /dev/kvm の権限を確認
ls -la /dev/kvm
# runner ユーザが kvm グループに所属しているか確認
groups github-runner
```

---

## 8. メンテナンス

### runner のアップデート

GitHub Actions runner は自動アップデートされる。手動更新が必要な場合:

```bash
sudo su - github-runner
cd ~/actions-runner
sudo ./svc.sh stop
# 新しいバージョンをダウンロード・展開
sudo ./svc.sh start
```

### Docker イメージのクリーンアップ

定期的にディスクスペースを回収する:

```bash
# 未使用イメージ・コンテナの削除
docker system prune -af

# containerlab が残したネットワークの削除
docker network prune -f
```

### ディスク使用量の監視

```bash
# ディスク使用量を確認
df -h /home/github-runner

# Docker のディスク使用量
docker system df
```

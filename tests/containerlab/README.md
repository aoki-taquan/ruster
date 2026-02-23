# containerlab E2E Tests

containerlab (Linux kind) を使った実パケット最小 E2E テスト。

## Topology

```
 +-----------+        +---------+        +-----------+
 | lan-host  | eth1 --| ruster  |-- eth2 | wan-host  |
 | .1.100/24 |        | .1.1/24 |        | .0.100/24 |
 +-----------+        | .0.1/24 |        +-----------+
                      +---------+
  192.168.1.0/24 (LAN)           10.0.0.0/24 (WAN)
```

- **ruster** — ルータノード (Debian bookworm-slim, ruster バイナリをマウント)
- **lan-host** — LAN 側ホスト (192.168.1.100/24)
- **wan-host** — WAN 側ホスト (10.0.0.100/24)

## Prerequisites

- **Linux** (containerlab は Linux 専用)
- **Docker** (running)
- **containerlab** v0.44+: https://containerlab.dev/install/
- **ruster バイナリ**: `cargo build --release`

> macOS / Windows では動作しない。Linux CI もしくは Linux 開発マシンで実行すること。

## Quick Start

```bash
# 1. ruster バイナリをビルド
cargo build --release

# 2. ワンショット E2E (deploy -> test -> destroy)
make clab-e2e

# または個別に実行
make clab-deploy     # トポロジ展開
make clab-test       # テスト実行
make clab-destroy    # トポロジ破棄
```

## Test Suites

| Script | 内容 |
|--------|------|
| `test-l2.sh` | ARP 解決、MAC アドレス学習 |
| `test-l3.sh` | ローカル配信、ルーティング、traceroute |
| `test-nat.sh` | NAT 透過、送信元変換、コネクショントラッキング |
| `test-fw.sh` | 許可トラフィック通過、拒否トラフィック遮断 (ベースライン) |
| `run-all.sh` | 全テスト一括実行 + サマリ |

## Running Individual Tests

```bash
# トポロジが起動済みの状態で:
cd tests/containerlab
bash scripts/test-l2.sh
bash scripts/test-l3.sh
bash scripts/test-nat.sh
bash scripts/test-fw.sh
```

## Test Output

各テストは `[PASS]` / `[FAIL]` をテスト項目ごとに出力する。
失敗時は診断情報 (ping 出力、ARP テーブル、ルーティングテーブルなど) を表示する。

`run-all.sh` の最終出力例:

```
================================================================
  E2E Test Summary
================================================================

  [PASS] L2 (ARP / MAC Learning)
  [PASS] L3 (Routing)
  [PASS] NAT (NAPT44)
  [PASS] Firewall

Total: 4 suites, 4 passed, 0 failed

RESULT: PASS
```

## Troubleshooting

### containerlab deploy が失敗する

```bash
# Docker が起動しているか確認
sudo systemctl status docker

# containerlab のバージョン確認
containerlab version

# 前回のトポロジが残っている場合
sudo containerlab destroy --topo topology.yml --cleanup
```

### ノードに手動で入る

```bash
# ruster ノード
docker exec -it clab-ruster-e2e-ruster bash

# lan-host
docker exec -it clab-ruster-e2e-lan-host bash

# wan-host
docker exec -it clab-ruster-e2e-wan-host bash
```

### テストが FAIL する

1. トポロジが正常に展開されたか確認:
   ```bash
   sudo containerlab inspect --topo topology.yml
   ```

2. 各ノードのインタフェース/ルートを確認:
   ```bash
   docker exec clab-ruster-e2e-ruster ip addr show
   docker exec clab-ruster-e2e-ruster ip route show
   docker exec clab-ruster-e2e-lan-host ip addr show
   docker exec clab-ruster-e2e-lan-host ip route show
   ```

3. ruster バイナリがマウントされているか確認:
   ```bash
   docker exec clab-ruster-e2e-ruster ls -la /usr/local/bin/ruster
   ```

### firewall テストが "baseline" と表示される

containerlab の Linux kind ではカーネルの IP 転送がパケット処理を行う。
ruster のデータプレーン (DPDK) がアクティブでない状態では、ruster の firewall ルールはカーネルレベルでは適用されない。
firewall テストは「ベースライン」として接続性とルート構成を確認し、ruster データプレーン稼働時に実際のフィルタリングが機能することを前提とする。

# Soak Tests (Long-Running Stability Regression)

ruster の長時間安定性を検証するソークテスト。メモリリーク、プロセスクラッシュ、リソース枯渇などの回帰を検出する。

## Purpose

ソークテストは以下の安定性回帰を検出する:

- **メモリリーク**: RSS が時間経過とともに無制限に増加していないか
- **プロセスクラッシュ**: ruster プロセスが予期せず終了していないか
- **CPU 異常**: CPU 使用率が閾値を超えていないか
- **FD リーク**: ファイルディスクリプタが増加し続けていないか
- **セッションテーブル枯渇**: コネクショントラッキングのリーク検出

## Prerequisites

- **Rust toolchain** (ruster バイナリのビルド)
- **bash** 4.0+
- `ps`, `awk`, `date` コマンド (POSIX 標準)

containerlab モード (Linux のみ):
- Docker
- containerlab v0.44+

## Quick Start

```bash
# 30 分間のソークテスト (デフォルト)
make soak-test

# 5 分間のクイックテスト
make soak-test-short

# カスタム設定で実行
SOAK_DURATION_MIN=60 SOAK_CHECK_INTERVAL=30 make soak-test
```

## Modes

### Standalone (デフォルト)

ruster バイナリを起動し、プロセスの健全性を監視する。v0.1 では DPDK I/O が未実装のため、実パケットは送信しない。プロセスの安定性とメモリ挙動のみを検証する。

```bash
# standalone モード (デフォルト)
bash tests/soak/soak-test.sh

# または明示的に指定
SOAK_MODE=standalone bash tests/soak/soak-test.sh
```

### Containerlab (Linux のみ)

containerlab トポロジを展開し、実パケット (ping/iperf) を送信しながら ruster を監視する。

```bash
SOAK_MODE=containerlab bash tests/soak/soak-test.sh
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SOAK_DURATION_MIN` | `30` | テスト時間 (分) |
| `SOAK_MODE` | `standalone` | 動作モード (`standalone` / `containerlab`) |
| `SOAK_CHECK_INTERVAL` | `60` | ヘルスチェック間隔 (秒) |
| `SOAK_OUTPUT_DIR` | auto | 出力ディレクトリ (自動生成) |
| `RUSTER_BIN` | `target/release/ruster` | ruster バイナリパス |
| `RUSTER_CONFIG` | `tests/containerlab/configs/ruster.toml` | 設定ファイルパス |

### Thresholds (thresholds.toml)

メトリクスの閾値は `thresholds.toml` で定義する:

```toml
[memory]
max_rss_growth_mb = 50      # ベースラインからの最大 RSS 増加量 (MB)
max_rss_absolute_mb = 256   # RSS の絶対最大値 (MB)

[process]
must_be_alive = true        # プロセスは最後まで生存していること
max_cpu_percent = 80        # CPU 使用率の上限 (%)

[stability]
max_restarts = 0            # 許容される再起動回数
min_uptime_fraction = 0.99  # 最小稼働率 (0.0 - 1.0)
```

## Output

テスト結果は `tests/soak/results/<timestamp>/` に出力される:

```
results/20260223-143000/
  metrics.tsv       # 生メトリクス (TSV)
  metrics-clean.tsv # コメント行を除いたメトリクス
  ruster.log        # ruster プロセスのログ
  report.md         # マークダウンレポート
```

## Reading the Report

レポート (`report.md`) には以下が含まれる:

1. **Test Parameters** — テスト条件 (時間、プラットフォーム、ホスト名)
2. **Memory (RSS)** — メモリ使用量のサマリ (ベースライン、最終値、成長量、最小/最大/平均)
3. **CPU** — CPU 使用率のサマリ
4. **File Descriptors** — ファイルディスクリプタ数のサマリ
5. **Process Stability** — プロセス生存状況
6. **Threshold Checks** — 各閾値の合否判定
7. **Overall Verdict** — 総合判定 (PASS/FAIL)

### 判定例

```
| Check              | Actual   | Threshold     | Result |
|--------------------|----------|---------------|--------|
| RSS growth         | 2.1 MB   | le 50 MB      | PASS   |
| RSS max            | 15.3 MB  | le 256 MB     | PASS   |
| Process alive      | yes      | must be alive | PASS   |
| CPU avg            | 3.2%     | le 80%        | PASS   |
| Restart count      | 0        | le 0          | PASS   |
| Uptime fraction    | 1.0000   | ge 0.99       | PASS   |
```

## Adjusting Thresholds

プロジェクトの成熟に伴い、閾値を段階的に厳格化する:

1. **v0.1 (現在)**: 緩めの閾値でベースラインを確立
2. **v0.2+**: 実 DPDK I/O 下での閾値を設定
3. **Production**: 本番負荷に基づく厳格な閾値

閾値の変更は `thresholds.toml` を編集する:

```bash
# 例: メモリ閾値を厳格化
vim tests/soak/thresholds.toml
```

## Scripts

| Script | Description |
|--------|-------------|
| `soak-test.sh` | メインオーケストレータ |
| `traffic-gen.sh` | トラフィック生成 (standalone/containerlab) |
| `check-health.sh` | ヘルスメトリクス収集 (1 サンプル) |
| `report.sh` | レポート生成 + 閾値チェック |

## CI Integration

自己ホストランナー (`self-hosted-runner.yml`) で定期実行する場合:

```yaml
# .github/workflows/soak-test.yml
name: Soak Test
on:
  schedule:
    - cron: '0 3 * * 1'  # 毎週月曜 03:00 UTC
  workflow_dispatch:

jobs:
  soak:
    runs-on: self-hosted
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: cargo build --release
      - name: Soak test
        run: make soak-test
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: soak-report
          path: tests/soak/results/
```

## Troubleshooting

### ruster バイナリが見つからない

```bash
# リリースビルドを実行
cargo build --release

# バイナリパスを明示的に指定
RUSTER_BIN=./target/release/ruster make soak-test
```

### Standalone モードで "surrogate process" が表示される

v0.1 では DPDK が未実装のため、ruster バイナリが起動直後に終了することがある。この場合、テストインフラの検証のために代替プロセスが自動的に起動される。これは正常な動作。

### containerlab モードでトポロジ展開が失敗する

```bash
# Docker が起動しているか確認
sudo systemctl status docker

# 前回のトポロジが残っている場合
sudo containerlab destroy --topo tests/containerlab/topology.yml --cleanup

# containerlab のバージョン確認
containerlab version
```

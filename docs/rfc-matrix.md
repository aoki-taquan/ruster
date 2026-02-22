# RFC 準拠管理マトリクス

ruster v0.1 が準拠・参照する RFC とその実装状況を管理する。

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue |
|------|----------|----------|----------|-------|
| Ethernet frame | IEEE 802.3 | フレーム解析・生成 | 未着手 | #90 (I-005) |
| ARP | RFC 826 | Request/Reply 処理 | 未着手 | #92 (I-007) |
| IPv4 | RFC 791 | ヘッダ解析・TTL・checksum | 未着手 | #90, #93 |
| ICMP | RFC 792 | Echo, Unreachable | 未着手 | #90 |
| TCP | RFC 9293 | ヘッダ解析 (conntrack 用) | 未着手 | #90, #94 |
| UDP | RFC 768 | ヘッダ解析 | 未着手 | #90 |
| NAT | RFC 3022 / RFC 4787 | NAPT, Port Forward | 未着手 | #95 |
| IP Forwarding | RFC 1812 | L3 転送要件 | 未着手 | #93 |

## 凡例

- **未着手**: Issue 作成済み、実装未開始
- **実装中**: `wip` ラベル付き Issue で作業中
- **完了**: テスト pass、PR マージ済み
- **部分対応**: 必須要件の一部のみ実装

## RFC コメント規約

コード中の RFC 準拠・非準拠は以下のコメント形式で管理する。

### RFC-REF（準拠根拠）

```rust
// RFC-REF: RFC 791 Section 3.1
// IPv4 header の Total Length は header + data の合計バイト数
```

### RFC-DEVIATION（非準拠の明示）

```rust
// RFC-DEVIATION:
// reason: home-lab 用途で実装コストを優先
// impact: 特定の相互接続で非互換の可能性
// issue: #95
// plan: v0.2 で準拠化
```

CI で 4 フィールド (`reason`, `impact`, `issue`, `plan`) の有無を自動検証する。

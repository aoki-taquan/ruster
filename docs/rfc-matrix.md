# RFC 準拠管理マトリクス

ruster v0.1 が準拠・参照する RFC とその実装状況を管理する。

## L2 / Ethernet

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| Ethernet frame | IEEE 802.3 / RFC 894 | フレーム解析・生成 | ✅ 実装済み | #90 (I-005) | `packet/ethernet.rs`, `l2/` |
| ARP | RFC 826 | Request/Reply 処理, キャッシュ管理 | ✅ 実装済み | #92 (I-007) | `arp/` — gratuitous ARP, aging, hold queue 対応 |

## L3 / IPv4

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| IPv4 | RFC 791 | ヘッダ解析・TTL・checksum | ✅ 実装済み | #90, #93 | `packet/ipv4.rs`, `routing/` |
| IP Forwarding | RFC 1812 | L3 転送要件 (LPM, TTL decrement) | ✅ 実装済み | #93 | `routing/` — RIB/FIB 分離, LPM, admin distance |
| ICMP | RFC 792 | Echo, Time Exceeded, Unreachable | ✅ 実装済み | #90 | `icmp.rs`, `packet/icmp.rs` — ループ防止対応 |

## L3 / IPv6

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| IPv6 | RFC 8200 | ヘッダ解析・Hop Limit・ルーティング | ✅ 実装済み | — | `packet/ipv6.rs`, `routing/ipv6_table.rs` |
| ICMPv6 | RFC 4443 | メッセージ解析 | ⚠️ 部分実装 | #159 | `packet/icmpv6.rs` — 解析は実装済み, error generation 未実装 (RFC-DEVIATION) |
| Neighbor Discovery | RFC 4861 | NS/NA 処理, キャッシュ管理 | ✅ 実装済み | — | `nd/`, `packet/icmpv6.rs` — NS/NA/SLLA option 対応 |

## L4 / Transport

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| TCP | RFC 9293 | ヘッダ解析 (conntrack 用) | ✅ 実装済み | #90, #94 | `packet/tcp.rs`, `conntrack/` — TCP state machine 対応 |
| UDP | RFC 768 | ヘッダ解析 | ✅ 実装済み | #90 | `packet/udp.rs` |

## NAT / Connection Tracking

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| NAT | RFC 3022 / RFC 4787 | NAPT, Port Forward, Hairpin | ⚠️ 部分実装 | #95 | `nat/` — NAPT44, port forward, hairpin 実装済み; ICMPv6 NAT 未実装 (RFC-DEVIATION #159) |
| Conntrack | RFC 7857 / RFC 6146 | 5-tuple session tracking, GC | ✅ 実装済み | #94 | `conntrack/` — TCP/UDP/ICMP session, timeout GC |

## Stateful Firewall

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| Stateful FW | — | Zone/Chain/Proto/State matching | ✅ 実装済み | #96 | `firewall/` — input/forward/output chain, established tracking |

## Routing Protocols

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| OSPFv2 | RFC 2328 | Hello/LSA/SPF/RIB 連携 | ⚠️ 部分実装 | #157 | `ospf/` — Hello, neighbor FSM, LSDB, SPF 実装済み; DR/BDR election, multi-area, auth 未実装 (RFC-DEVIATION #157) |
| BGP-4 | RFC 4271 | OPEN/UPDATE/FSM/best-path | ⚠️ 部分実装 | #158 | `bgp/` — eBGP FSM, UPDATE parse, best-path 実装済み; iBGP, 4-byte ASN, MP-BGP 未実装 (RFC-DEVIATION #158) |

## SRv6

| 機能 | 対象 RFC | 必須要件 | 実装状況 | Issue | 備考 |
|------|----------|----------|----------|-------|------|
| SRv6 Network Programming | RFC 8986 | End/End.DT4/End.DT6/uN actions | ⚠️ 部分実装 | #160 | `srv6/` — SID table, uSID, basic actions 実装済み; SRH TLV, SL rewrite, full decap 未実装 (RFC-DEVIATION #160) |
| SRH | RFC 8754 | Segment Routing Header 解析 | ⚠️ 部分実装 | #160 | `srv6/srh.rs` — SRH parse/serialize 実装済み; TLV 非対応 (RFC-DEVIATION #160) |

---

## 凡例

- ✅ **実装済み**: テスト pass、PR マージ済み
- ⚠️ **部分実装**: 必須要件の一部のみ実装 — RFC-DEVIATION で非準拠箇所を管理
- ❌ **未着手**: Issue 作成済み、実装未開始

## RFC-DEVIATION 一覧

全 RFC-DEVIATION の詳細は [`docs/rfc-deviations.tsv`](rfc-deviations.tsv) を参照。

| 対象 | 件数 | 主な非準拠内容 | 対応 Issue |
|------|------|---------------|-----------|
| OSPF (RFC 2328) | 7 | DR/BDR election, multi-area, auth 未対応 | #157 |
| BGP (RFC 4271) | 10 | iBGP, 4-byte ASN, MP-BGP 未対応 | #158 |
| ICMPv6 / NAT | 2 | ICMPv6 conntrack / NAT 未対応 | #159 |
| SRv6 (RFC 8986) | 5 | SRH TLV, SL rewrite, full decap 未対応 | #160 |
| Pipeline | 3 | SRH rewrite, inner packet re-injection, ICMPv6 Time Exceeded | #159, #160 |

---

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

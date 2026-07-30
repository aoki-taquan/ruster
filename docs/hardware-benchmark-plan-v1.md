# Hardware benchmark plan v1

`hardware_plan_v1`は`ruster.hardware-bench/v1` caseを決定的に列挙するNIC-free
pure plannerです。通常CIでcase集合、順序、seed、case ID、frame mathを検証します。
traffic generator、AF_XDP、PVE、hardware runner、threshold、baseline、pass/fail、
性能値の取得や性能主張は扱いません。

## Stable identity and order

- plan version: `1`
- ordinal: zero-based `0..=236`
- seed: `ordinal + 1`
- case ID:
  `v1:{mode}:q{queue_count}:b{batch_size}:{frame}:f{flow_count}:{direction}:{service}:{transport}`
- slice order: primary、flow-one、flow64-imix、single-queue、copy-mode、
  standalone-firewall、udp-zero、batch-sweep

各slice内では文書に記載した配列順で、frame、direction、service、transportの順に
nested enumerationします。plannerはcanonical IDの重複、期待集合からのmissing/
unexpected case、order、ordinal、seed、class driftを拒否します。
unit testは全237件のordinal、seed、class、case IDを含む非暗号学的regression fingerprint
`f2035b2fc3d22d89`も固定し、中間caseの意図しない変更を検出します。このfingerprintは
artifactの真正性や署名を表しません。

## Primary cases

primaryは次の直積90件です。

- mode: `zero-copy`
- queue count: `4`
- flow count: `4096`
- batch size: `64`
- frame: `eth64`, `eth128`, `eth512`, `ip-mtu1500`, `ruster-imix-v1`
- direction: `outbound`, `inbound`, `bidirectional`
- service: `plain`, `nat44`, `nat44-firewall`
- transport: `udp-checksum`, `tcp-checksum`

```text
5 frames × 3 directions × 3 services × 2 transports = 90
```

## Control cases

3-frame setは`eth64`, `eth512`, `ip-mtu1500`です。指定のないbatchは64、
transportは`udp-checksum`です。

| class | axes | count |
|---|---|---:|
| flow-one | zero-copy/q4/flow1 × 3 frames × 3 directions × 3 primary services | 27 |
| flow64-imix | zero-copy/q4/flow64 × IMIX × 3 directions × 3 primary services | 9 |
| single-queue | zero-copy/q1/flow4096 × 3 frames × 3 directions × 3 primary services | 27 |
| copy-mode | copy/q4/flow4096 × 3 frames × 3 directions × 3 primary services | 27 |
| standalone-firewall | zero-copy/q4/flow4096 × 3 frames × 3 directions × UDP/TCP | 18 |
| udp-zero | 4 mode/queue/flow profiles × 3 frames × 3 directions、service=`plain` | 36 |
| batch-sweep | batch 1/32/256、zero-copy/q4/flow4096/IMIX/bidirectional/nat44-firewall/UDP | 3 |

UDP-zeroの4 profilesは、zero-copy/q4/flow1、zero-copy/q4/flow64、
zero-copy/q1/flow4096、copy/q4/flow4096です。

```text
27 + 9 + 27 + 27 + 18 + 36 + 3 = 147 controls
90 + 147 = 237 total
```

## Frame and L1 convention

fixed frameのbackend bytesはFCSを含みません。Ethernet through FCSに
preamble/SFD 8 bytesとIFG 12 bytesを加えた値をL1 slotとします。

| frame | backend bytes | through FCS | L1 slot bytes |
|---|---:|---:|---:|
| `eth64` | 60 | 64 | 84 |
| `eth128` | 124 | 128 | 148 |
| `eth512` | 508 | 512 | 532 |
| `ip-mtu1500` | 1514 | 1518 | 1538 |

`ruster-imix-v1`は次のexact 12-packet cycleです。cycle内の順序も固定します。

```text
eth64 × 7, eth512 × 4, ip-mtu1500 × 1
cycle L1 bytes = 7×84 + 4×532 + 1×1538 = 4254
```

## Exact line-rate arithmetic

fixed frameのpacket rateは
`bits_per_second / (L1 slot bytes × 8)`、IMIXは
`bits_per_second × 12 / (4254 × 8)`です。plannerは分子・分母をGCDで約分した
`ExactPacketRate`を返します。integer offered rate用の`floor_pps`は切り捨てで、
line rateを超えるround-upを行いません。

10,000,000,000 bits/sのknown answers:

| frame | reduced rational | floor packets/s |
|---|---:|---:|
| `eth64` | 312500000 / 21 | 14880952 |
| `eth128` | 312500000 / 37 | 8445945 |
| `eth512` | 312500000 / 133 | 2349624 |
| `ip-mtu1500` | 625000000 / 769 | 812743 |
| `ruster-imix-v1` | 2500000000 / 709 | 3526093 |

zero bit rateを拒否します。この算術はoffered plan作成用であり、accepted throughput、
loss、latency、threshold合否を表しません。

## NIC-free acceptance

通常unit testは次を固定します。

- classごとの90/147/237 exact count
- 全case IDのunique性とmissing/unexpected/duplicate rejection
- stable order、ordinal、seed、first/last case ID
- 全237 caseのhardware artifact schema roundtrip
- fixed frame byte known answers
- IMIXの7:4:1 count、cycle order、4254 L1 bytes
- 10GbE exact rationalとfloor known answers

実測artifact、runner lifecycle、PVE orchestration、signature、threshold evaluatorは
このplanとは別のreview単位です。

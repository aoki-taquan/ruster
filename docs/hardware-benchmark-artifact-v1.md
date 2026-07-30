# Hardware benchmark artifact schema v1

`ruster.hardware-bench/v1`は、review済みbenchmark specificationに対して将来の専用
hardware runnerが保存するartifactのschema契約です。通常CIでNICなしにparse、
validation、canonical serialization、redactionを検証できます。

この実装はhardwareを操作せず、trafficを生成せず、AF_XDP queueを所有せず、PVEや
runner、secret、CI permissionを設定しません。また、threshold、pass/fail判定、
baseline、回帰判定、性能値の主張を含みません。既存のNIC-free `ruster-bench`
`ResultRow` JSONL schemaとは独立しており、そのfieldや意味を変更しません。

## Envelope and records

すべてのrecordは次のenvelopeを持ちます。

| field | value |
|---|---|
| `schema_id` | exact `ruster.hardware-bench/v1` |
| `schema_version` | integer `1` |
| `kind` | `manifest`, `repeat`, `summary`, `lifecycle`のいずれか |

unknown field、missing field、重複JSON key、unknown enum、異なるschema ID/versionは
fail closedで拒否します。integer fieldはJSON integerとして範囲内でなければならず、
metricは有限かつ非負でなければなりません。表現を一意にするためnegative zeroも拒否します。
loss ratioは`0.0..=1.0`です。JSON inputは1 MiB以下、container nestingは64段以下です。

### `manifest`

1 runにつき1 recordです。

- `run_id`
- `spec_git_sha`, `spec_sha256`
- `source_git_sha`, `source_dirty`
- `hardware_profile_id`, `build_profile`, `rustc`
- `kernel_release`, `kernel_cmdline_sha256`
- `cpu_model`, `cpu_microcode`
- `worker_cpu_mask`, `irq_cpu_mask`, `housekeeping_cpu_mask`, `numa_node`
- `nic_pci_id`, `nic_driver`, `nic_firmware`
- `xdp_program_sha256`
- `offload_profile_id`, `rss_profile_id`, `generator_id`
- `artifact_hashes`

再現性のため、spec/source SHAと環境profile IDを値そのものと分離します。
`source_dirty`はv1では必ず`false`です。hostname、management address、MAC、
serialなどのlab topologyをmanifestへ入れてはいけません。

### `repeat`

1 caseの1 measured repeatです。case fieldsは`mode`, `queue_count`, `batch_size`,
`frame`, `flow_count`, `direction`, `service`, `transport`です。次のenumだけを
受理します。

- `mode`: `copy`, `zero-copy`
- `frame`: `eth64`, `eth128`, `eth512`, `ip-mtu1500`, `ruster-imix-v1`
- `direction`: `outbound`, `inbound`, `bidirectional`
- `service`: `plain`, `nat44`, `firewall`, `nat44-firewall`
- `transport`: `udp-zero`, `udp-checksum`, `tcp-checksum`

`case_id`は次のcase fieldsから一意に導出し、一致しないrecordを拒否します。

```text
v1:{mode}:q{queue_count}:b{batch_size}:{frame}:f{flow_count}:{direction}:{service}:{transport}
```

measurement fieldsは`repeat_index`, `warmup_seconds`, `duration_seconds`,
`offered_packets`, `received_packets`, `accepted_packets`, `loss_packets`,
`accepted_pps`, `l1_gbps`, `loss_ratio`, `latency_samples`, `p50_latency_ns`,
`p99_latency_ns`です。`duration_seconds`は推定値や丸めたwall-clockではなく、
counterを取得したmeasurement intervalのexact integer secondsです。packet countは
`accepted <= received <= offered`かつ`loss = offered - received`を満たし、
`accepted_pps`は`(accepted_packets as f64) / (duration_seconds as f64)`の
binary64結果とbit単位で一致する必要があります。
`loss_ratio`は`loss as f64 / offered as f64`のbinary64結果とbit単位で一致する必要が
あります。`offered = 0`の場合はpacket countと`loss_ratio`をすべてzeroと定義します。
`latency_samples = 0`の場合はp50/p99もzeroでなければならず、sampleがある場合は
finite/nonnegativeかつ`p99 >= p50`でなければなりません。

fixed frameの`l1_gbps`はaccepted packet countから導出します。L1 byte countはFCS、
preamble/SFD、IFGを含み、eth64=84、eth128=148、eth512=532、
ip-mtu1500=1538 bytesです。計算は
`(l1_bit_count as f64) / ((duration_seconds as f64) * 1_000_000_000.0)`の
binary64結果とのbit一致を要求します。`duration_seconds`で割ってから`1e9`で割る
sequential evaluationは丸め順が異なるため使用しません。

`ruster-imix-v1`はaggregate packet countだけからL1 bit countを復元できません。
IMIX repeatは`imix_accepted_frames` objectに`eth64_packets`, `eth512_packets`,
`ip_mtu1500_packets`を必須で持ち、そのchecked sumが`accepted_packets`と一致する必要が
あります。`l1_gbps`はこのsize別accepted countと上記L1 byte countから導出します。
fixed-frame repeatがこのIMIX evidenceを持つことも拒否します。これによりIMIXの
`l1_gbps`を未拘束の自己申告値にしません。

`frame_health_before`と`frame_health_after`は、backend ownership lifecycleの
境界snapshotです。`total`は`free + fill + rx_owned + core_borrowed + tx_owned +
completion`と一致する必要があります。`invalid_descriptors`と`double_owned`は
diagnostic counterで、所有数の合計には含めません。加算overflowを拒否し、同じrepeatの
before/afterで`total`が変わるrecordも拒否します。

### `summary`

case fieldsとcanonical `case_id`に加え、`repeat_count`, `accepted_pps_median`,
`l1_gbps_median`, `loss_ratio_worst`, `p50_latency_ns_worst`,
`p99_latency_ns_worst`, `artifact_hashes`を持ちます。

summaryは観測値の保存形式です。thresholdやpass/fail fieldはv1 schemaに存在しません。

### `lifecycle`

runのordered eventとして`sequence`, `monotonic_ms`, `phase`, `outcome`, `code`,
`frame_health`, `artifact_hashes`を持ちます。

- `phase`: `preflight`, `setup`, `warmup`, `measurement`, `drain`, `cleanup`
- `outcome`: `started`, `completed`, `failed`

`code`は機械処理用のpublic IDです。hardware runnerが実装される際は、失敗時も
cleanupを含むlifecycle recordをappend-onlyで保存する必要があります。

## Hash and canonical JSON contract

各`artifact_hashes` elementはsafe relative `path`と64文字のlowercase hexadecimal
`sha256`を持ちます。absolute path、`.`/`..` component、unsafe character、重複pathを
拒否します。recordを含むfile自身をhash一覧へ含めて自己参照させてはいけません。

canonical JSONはobject keyをlexicographic順、artifact hashをpath順に出力し、余分な
whitespaceを持ちません。4種類のgolden fixture自身をcanonical JSON bytesの直後にexactly
one LFを持つfileとしてcheck inします。testはtrimせず`fixture == canonical + "\n"`を固定し、
leading/trailing spaceや余分なLFを非canonicalと判定します。再parse後も同じcanonical bytesに
なることを通常unit testで検証します。field値の変更はfixture file hashも変更するため、
artifact producerは更新後のexact bytesをhash対象にします。schema layerはartifact bytesの
hash計算やfile I/Oを行いません。

## Redaction boundary

`redact_sensitive_json`は任意のJSON object/arrayを再帰的に処理します。keyのASCII case、
camelCase境界、連続separatorをsegmentへ正規化し、次のdenylistをsegment、隣接segment、
またはcommon collapsed spellingとして検出したfieldを削除します。

```text
hostname fqdn management_ip management_url mac_address serial_number
runner_token token secret password credential private_key ssh_key topology
```

たとえば`token_value`、`topology_map`、`host-name`、`macAddress`も削除対象です。

出力はcanonical JSONです。redactionはfield-name boundaryであり、secret scannerや
認証情報保管機能ではありません。runnerは最小限のallowlisted metadataだけを作り、
redaction後のartifactに対して別のsecret scanning gateを実施する必要があります。

## Golden fixtures

v1 fixtureは
[`crates/bench/tests/fixtures/hardware-bench-v1`](../crates/bench/tests/fixtures/hardware-bench-v1)
にあります。fixtureはschemaの互換性検査用であり、実NICのmeasurement結果でも
性能baselineでもありません。

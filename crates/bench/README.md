# ruster-bench

`ruster-core`のpacket leaseと同じ境界を使う、NIC不要・外部crate依存なしの
benchmark runnerです。`ruster-io-sim`の投入/capture用queueを測定に含めず、
事前確保したbackend所有bufferをcoreへ借用させます。

```bash
cargo run --release -p ruster-bench -- \
  --suite smoke --format human

cargo run --release -p ruster-bench -- \
  --suite datapath --format jsonl
```

現在のsuiteはplain IPv4 forwardingとInternet checksumのone-pass / two-pass controlに加え、
UDP/TCPのoutbound/inbound established flowを、matched plain control、NAT44、
stateful firewall、NAT44+firewallの4 profileで測定します。UDPはchecksum zero/nonzeroを
分離し、TCPはfull checksumを持つfixtureを使います。state確立はtimed region外です。
`checksum_passes`はtransport payload全体を走査するfull checksum検証回数を表し、
NAT44のRFC 1624 incremental checksum updateは数えません。

`wire64`はbackend buffer 60 bytes、FCS込みEthernet 64 bytes、preamble/SFDとIFG込み
84 bytesです。`ip-mtu1500`はそれぞれ1514、1518、1538 bytesです。結果のJSONLにも
全ての値を別fieldで保存します。

fixture生成、結果検証、formattingはtimed region外です。buffer resetとbatch acquisitionの
costは次のaggregate subtractionで結果から除外します。測定interval内でcurrent worker
threadのallocationを一つでも検出したrunは失敗します。
各forwarding caseは同じ反復数の`reset + receive` intervalを別に一度測り、全反復を一つの
intervalで測った値から差し引きます。packetごとのclock読取りを入れず、batchごとの
`forward_batch`/finish境界を維持します。
短いcalibration probeでcontrolがmeasured intervalを上回った場合は反復数を増やします。
正式sampleで同じ状態になった場合はzeroへ丸めず、両Durationを持つtyped errorで失敗します。
各packet bufferは測定直前のresetでCPU cacheへ触れるため、これはcoreのhot-cache
microbenchmarkであり、NIC/backend DMAやcold-cache throughputの主張ではありません。

比較するrunでは同じRust toolchain、target、`RUSTFLAGS`、CPU、governor、pinning、
suite引数を使用し、実行commandとJSONLを一緒に保存してください。host固有の値を
異なるmachine間でbaselineとして比較する用途は想定していません。

## Hardware artifact schema

`ruster.hardware-bench/v1`は、将来の専用hardware runnerが出力するmanifest、repeat、
summary、lifecycle recordの厳格なNIC不要schemaです。このcrateはrecordのparse、
validation、canonical JSONL化、機密fieldのredactionだけを提供します。hardwareへの
アクセス、traffic生成、runner制御、合否threshold、性能主張は行いません。既存の
`ResultRow` JSONL schemaは変更しません。

field、enum、case ID、frame ownership、hash、redactionの契約とgolden fixtureは
[hardware benchmark artifact v1](../../docs/hardware-benchmark-artifact-v1.md)を
参照してください。

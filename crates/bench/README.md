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

現在のfoundation suiteはplain IPv4 forwardingとInternet checksumのone-pass /
two-pass controlを測定します。NAT/firewall/state pressureは後続sliceです。

`wire64`はbackend buffer 60 bytes、FCS込みEthernet 64 bytes、preamble/SFDとIFG込み
84 bytesです。`ip-mtu1500`はそれぞれ1514、1518、1538 bytesです。結果のJSONLにも
全ての値を別fieldで保存します。

fixture生成、結果検証、formattingはtimed region外です。buffer resetとbatch acquisitionの
costは次のaggregate subtractionで結果から除外します。測定interval内でcurrent worker
threadのallocationを一つでも検出したrunは失敗します。
plain forwardingは同じ反復数の`reset + receive` intervalを別に一度測り、全反復を一つの
intervalで測った値から差し引きます。packetごとのclock読取りを入れず、batchごとの
`forward_batch`/finish境界を維持します。
短いcalibration probeでcontrolがmeasured intervalを上回った場合は反復数を増やします。
正式sampleで同じ状態になった場合はzeroへ丸めず、両Durationを持つtyped errorで失敗します。
各packet bufferは測定直前のresetでCPU cacheへ触れるため、これはcoreのhot-cache
microbenchmarkであり、NIC/backend DMAやcold-cache throughputの主張ではありません。

比較するrunでは同じRust toolchain、target、`RUSTFLAGS`、CPU、governor、pinning、
suite引数を使用し、実行commandとJSONLを一緒に保存してください。host固有の値を
異なるmachine間でbaselineとして比較する用途は想定していません。

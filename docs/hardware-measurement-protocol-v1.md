# Hardware measurement protocol v1

`HardwareMeasurementProtocol`は、frozen 237-case hardware planに対する実測入力を
NIC-freeかつdependency-freeに検証する契約です。driver、filesystem、Linux/PVE、
AF_XDP、traffic生成、resume、threshold、baseline、pass/fail、性能主張は扱いません。

## Frozen binding

protocol versionは`1`、plan versionは`1`、plan regression fingerprintは
`f68c80b72065c023`です。fingerprintは237件の順序、ordinal、seed、class、canonical
case ID、およびordered IMIX cycleにbindします。これはplan drift検出値であり、
暗号学的hashや署名ではありません。

各runは次のtyped inputを必須にします。

- spec Git commit: lowercase 40-hex
- spec content: SHA-256 lowercase 64-hex
- source Git commit: lowercase 40-hex
- generator profile: 1..=64 bytesのcanonical IDと設定SHA-256
- latency profile: disabled、round-trip、またはclock evidence SHA-256付きone-way
- timing: bounded warmup、nonzero bounded duration、odd repeat count、case/drain/run timeout

warmupとdurationは各600秒以下、repeat countは1..=31の奇数です。drainは
1..=600,000 ms、caseは最大6時間、runは最大60日です。case timeoutは
`warmup + duration × repeats + drain`以上、run timeoutは`case timeout × 237`
以上でなければなりません。

## Integer observations

`RawRepeatCounters`はuntrusted inputです。counterは同じprotocol/case/repeatのtyped
measurement lifecycle pairへbindします。pairはadjacentな`started`/`completed`で、
observed intervalがdeclared durationとmillisecond単位でexact一致しなければなりません。
短い、長い、別case/repeatへdetachedしたintervalはrate導出前に拒否します。
`VerifiedRepeat::from_raw`だけがartifact recordを生成します。各active directionはofferedがnonzeroで、
`received <= offered`かつ`accepted == received`でなければなりません。inactive
directionは全counterがexact zeroです。duplicate、unexpected、packet oracle failureは
いずれもexact zeroを要求します。direction合計とL1 bit countはchecked integer
arithmeticで計算します。

fixed frameはIMIX evidenceを拒否します。`ruster-imix-v1`はactive directionごとに
accepted frame-size evidenceを必須とし、その3 sizeの合計がdirectionのaccepted
packet数とexact一致しなければなりません。bidirectional caseはoutbound/inboundを
別々に検証してからchecked addします。loss、pps、L1 Gbpsは検証済みintegerとprotocol
durationからだけ導出します。

latency disabledではsampleとpercentileをexact zeroにします。有効時のsample数は
`ceil(accepted_packets / sample_every_packets)`とexact一致し、nonempty percentileは
positiveかつ`p99 >= p50`です。one-way profileはclock synchronization evidence hashを
型として保持します。

## Summary and completeness

`VerifiedSummary::derive`は同じprotocol/caseへbindされたexact odd repeat setだけを
受理します。repeat indexは`1..=R`が重複・欠落なく揃う必要があります。throughputは
median、lossとlatencyはworst valueをrepeat recordから決定的に導出します。

complete runはexactly 237 case、各case exactly R repeat、exactly 237 summaryです。
R=3ならrepeat recordは711件です。repeatはordinal outer/repeat index inner、
summaryはordinal順のcanonical orderを要求します。duplicate、missing、reorder、
別protocol/caseへのbinding、またはsupplied repeat setから再導出できないsummaryを
拒否します。

## Lifecycle

codeはfree-form入力ではなくtyped constructorで作成し、canonical labelへ変換します。

```text
run.preflight
run.setup
case.NNN.warmup
case.NNN.repeat.RRR.measurement
case.NNN.drain
run.cleanup
```

各codeはcontiguous sequenceとnondecreasing monotonic timeを持つ`started`、
続いて同一codeの`completed`または`failed`のpairです。正常系はpreflight、setup、
ordinal 0..236のwarmup、repeat 1..=R、drain、cleanupのexact順序です。
preflight/setup failureはcleanupへ、warmup/measurement failureは同じcaseのdrainを
経てcleanupへ遷移します。各eventでrun/case deadlineを、drain pairでdrain timeoutを
検証し、completed measurement pairはdeclared durationとのexact一致も要求します。
validator更新はtransactionalで、拒否eventは状態を進めません。

artifact hash inputは最大64件、各relative pathは最大256 bytesです。path昇順の
canonical orderを要求し、件数、path長、orderをrecord生成や内部cloneより前に検証します。

## Test boundary

通常CIはhash/profile/timingの境界、fixed/IMIX direction counter、latency sampling、
237×R completeness、summary再導出、lifecycleの正常・failure・gap・time regression・
phase skipをNICなしで検証します。実機driverとartifact persistenceは後続の独立した
review unitです。

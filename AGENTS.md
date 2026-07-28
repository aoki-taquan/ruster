# Agent policy

このrepositoryで作業するagentは次を守る。

- main agentは調整、計画、成果統合だけを担当し、コードを書かない。
- 実装とレビューは別々のsubagentへ委譲する。実装者は自分の変更を検証するが、
  独立レビューの代わりにはしない。
- agentは安全かつscope内ならcommit、push、PR作成、check監視、mergeを自動で進めてよい。
- prototype-v0.1からRust実装をcopyまたは改変しない。RFC根拠とblack-boxの
  入力/期待値だけを再利用できる。
- fast pathへ共有`Mutex`、packet clone、packet単位`String`、`dyn PacketIo`を入れない。
- 新しいbackendはbackend所有bufferをcoreへ借用させ、完了slotをcommitまたはrecycleする。
- 変更後はREADMEに記載したformat、clippy、test、doc、checkを実行する。

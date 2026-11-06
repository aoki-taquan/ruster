# Agent policy

作業の前に[`docs/charter.md`](docs/charter.md)を読む。何を作るかの判断はcharterに従う。

## 判断

- 新機能、scope、順序、milestoneはownerが決める。agentは提案までで、自分の判断で進めない。
- 今の利用目標に必要ない機能は作らない。RFCに書いてある、レビューで指摘された、は
  それだけでは作業の理由にならない。

## 作業の単位

- 1 PRに目的は一つ。テストを除く差分はおおむね500行まで。超えそうなら先に分け方を提案する。
- 機能追加のPRはownerがapproveしてからmergeする。fix、test、docs、choreはCIが通れば
  agentがmergeしてよい。
- PRのタイトルと本文は人が読む前提で、普通の言葉で書く。要件IDは本文の末尾に一行だけ。

## 実装とレビュー

- 実装は一つのagentが通しで行い、下の確認を自分で通す。
- 独立レビューを別agentに頼むのは、unsafe/FFI/syscall、NATやfirewallの状態、
  設定の反映や再読み込みに触る変更だけ。
- mergeを止めるのはCriticalとHighの指摘だけ。Medium以下は`docs/backlog.md`に一行で残し、
  そのためだけのPRは作らない。

## 守ること

- `prototype-v0.1`のRust実装をcopyしたり改変して使ったりしない。RFCと、入力と期待値の例だけ使える。
- 転送の処理経路に、共有`Mutex`、パケットのclone、パケットごとの`String`、`dyn PacketIo`を入れない。
- パケットのbufferはI/O層が持ち、転送部はそれを借りるだけ。借りたbufferは必ず送信か返却で終える。

## 書き方

- 普通の言葉で書く。新しい造語を作らない。
- READMEは200行以内。現在の進み具合は一か所だけに書く。
- 文書は追記より書き換えと削除を優先する。

## 確認

変更後はREADMEの「開発」にあるformat、clippy、test、doc、checkを実行する。

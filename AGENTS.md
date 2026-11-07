# Agent policy

作業の前に[`docs/charter.md`](docs/charter.md)を読む。何を作るかの判断はcharterに従う。

## 判断

- 新機能、scope、順序、milestoneはownerが決める。agentは提案までで、自分の判断で進めない。
- charterの「作るもの」に無い機能は作らない。RFCに書いてある、レビューで指摘された、は
  それだけでは作業の理由にならない。

## 作業の単位

- 1 PRに目的は一つ。テストを除く差分はおおむね500行まで。超えそうなら先に分け方を提案する。
- CIが通り、独立レビューが要る変更ではCriticalとHighの指摘が無ければ、agentが自分の判断でmergeしてよい
  （2026-11-06 owner決定）。charterや設計図の方針を変えるPRは、mergeの前にownerに確認する。
- PRのタイトルと本文は人が読む前提で、普通の言葉で書く。要件IDは本文の末尾に一行だけ。

## 実装とレビュー

- 実装は一つのagentが通しで行い、下の確認を自分で通す。
- 独立レビューを別agentに頼むのは、unsafe/FFI/syscall、NATやfirewallの状態、
  設定の反映や再読み込みに触る変更だけ。
- mergeを止めるのはCriticalとHighの指摘だけ。Medium以下は`backlog`ラベルのGitHub issueに残し、
  そのためだけのPRは作らない。

## 守ること

- `prototype-v0.1`のRust実装をcopyしたり改変して使ったりしない。RFCと、入力と期待値の例だけ使える。
- 転送の処理経路に、共有`Mutex`、パケットのclone、パケットごとの`String`、`dyn PacketIo`を入れない。
- パケットのbufferはI/O層が持ち、転送部はそれを借りるだけ。借りたbufferは必ず送信か返却で終える。

## 準拠するRFC

- 標準のある機能を作るときは、そのモジュールの先頭の説明（`//!`）に`# Standards`の節を置き、
  準拠するRFCの節と、外している点（Deviations）を書く。どのRFCに沿ったかはここだけに書く。

## 書き方

- 普通の言葉で書く。新しい造語を作らない。
- READMEは200行以内。現在の進み具合は一か所だけに書く。
- 文書は追記より書き換えと削除を優先する。

## 確認

変更後、mergeの前にREADMEの「開発」にあるformat、clippy、test、doc testをローカルで実行する。
CIは同じものを一つのjobで回すだけにしている。プロジェクトが大きくなってから足す。

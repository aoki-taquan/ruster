# issue-start

Issue 番号を受け取り、作業開始の準備を一括で行う skill。

## 引数

- `$ARGUMENTS` — Issue 番号 (例: `87`)

## 手順

1. `gh issue view <NUM> --json number,title,labels,state,milestone` で Issue 情報を取得する
2. Issue が OPEN でなければエラーで中断する
3. labels に `wip` が含まれていれば「既に着手中」と警告して中断する
4. title からスラッグを生成する（小文字化、スペースを `-` に、英数字とハイフン以外を除去、40文字以内に切り詰め）
5. `git worktree add .worktrees/<NUM>-<SLUG> -b issue/<NUM>-<SLUG> origin/main` で worktree を作成する
6. `gh issue edit <NUM> --add-label wip` で `wip` ラベルを付与する
7. 作成した worktree ディレクトリのパスを表示する
8. 「worktree で作業を開始してください」とユーザに案内する

## 例

```
/issue-start 87
```

→ Issue #87 の情報を取得し、`.worktrees/87-dpdk-base/` に worktree を作成、`wip` ラベル付与。

## 注意

- `origin/main` が最新であることを前提とする。必要なら事前に `git fetch origin` を実行する。
- worktree パスが既に存在する場合はスキップして既存パスを案内する。

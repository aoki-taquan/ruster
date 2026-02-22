# Worktree Start

Issue 番号と slug を受け取り、作業用 Git worktree を作成する。

## 引数

- `$ARGUMENTS` — `<NUM> <SLUG>` 形式 (例: `87 dpdk-base`)

## 手順

1. 引数から NUM と SLUG を取得する
2. worktree パス `.worktrees/<NUM>-<SLUG>` を確認し、既存なら中断する
3. `git worktree add .worktrees/<NUM>-<SLUG> -b issue/<NUM>-<SLUG> origin/main` を実行する
4. 作成した worktree ディレクトリに cd する
5. 完了メッセージを表示する

## 実行例

```
/worktree-start 87 dpdk-base
```

→ `.worktrees/87-dpdk-base/` に worktree が作成され、ブランチ `issue/87-dpdk-base` が作成される。

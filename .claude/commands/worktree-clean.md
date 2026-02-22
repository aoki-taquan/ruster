# Worktree Clean

指定した worktree を削除し、対応するブランチも cleanup する。

## 引数

- `$ARGUMENTS` — `<NUM> <SLUG>` 形式 (例: `87 dpdk-base`)

## 手順

1. 引数から NUM と SLUG を取得する
2. worktree パス `.worktrees/<NUM>-<SLUG>` が存在するか確認する
3. `git worktree remove .worktrees/<NUM>-<SLUG>` を実行する
4. ブランチ `issue/<NUM>-<SLUG>` がマージ済みなら `git branch -d issue/<NUM>-<SLUG>` で削除する
5. `git worktree prune` を実行する
6. 完了メッセージを表示する

## 実行例

```
/worktree-clean 87 dpdk-base
```

→ `.worktrees/87-dpdk-base/` とブランチ `issue/87-dpdk-base` が削除される。

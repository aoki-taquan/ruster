---
name: issue-start
description: GitHub Issueの作業を開始する。ブランチを作成してチェックアウト。「/issue-start 4」のように使用
allowed-tools: Bash(git:*), Bash(gh:*)
---

# Issue Start

## Instructions

1. 引数でIssue番号を受け取る（例: `/issue-start 4`）
2. `gh issue view <number> --json title,labels` でIssueタイトルとラベルを取得
3. `wip` ラベルがあれば警告して中止（既に作業中）
4. タイトルからslugを生成（小文字、スペースをハイフンに、記号削除）
5. mainブランチを最新に取得: `git fetch origin main`

## Worktree クリーンアップ

6. `git worktree list` で既存worktreeを確認
7. 各worktreeについて（メインリポジトリ以外）:
   - パスから `ruster-<number>` 形式を探す
   - ブランチ名から `feature/<number>-xxx` を抽出
   - `gh pr list --head <branch> --state merged --json number` でマージ済みPRを確認
   - マージ済みなら「削除しますか？」とユーザーに質問
   - 承認されたら:
     - `git worktree remove <path>` でworktree削除
     - `git branch -d <branch>` でブランチ削除

## Worktree 作成

8. `gh issue edit <number> --add-label wip` でラベル追加
9. `gh issue comment <number> -b "🔧 Started in worktree: ../ruster-<number>"` でコメント追加
10. `git worktree add ../ruster-<number> -b feature/<number>-<slug> origin/main` でworktree作成
11. 作業ディレクトリのパスを表示

## Example

```
/issue-start 12
```

実行結果:
```
Issue #12 "新機能XYZ" の作業を開始します

--- Worktree クリーンアップ ---
既存worktree: ../ruster-8 (feature/8-config-system)
  → PR #35 がマージ済みです。削除しますか？ [Y/n]
✓ ../ruster-8 を削除しました

--- 新規Worktree作成 ---
✓ wip ラベルを追加
✓ 作業開始コメントを追加
✓ Worktree作成: ../ruster-12

作業ディレクトリ: /home/aoki/ruster-12
ブランチ: feature/12-new-feature-xyz

このディレクトリで Claude Code を起動してください:
  cd ../ruster-12 && claude
```

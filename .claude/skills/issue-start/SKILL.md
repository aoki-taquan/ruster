---
name: issue-start
description: GitHub Issueの作業を開始する。ブランチを作成してチェックアウト。「/issue-start 4」のように使用
allowed-tools: Bash(git:*), Bash(gh:*)
---

# Issue Start

## Instructions

1. 引数でIssue番号を受け取る（例: `/issue-start 4`）
2. `gh issue view <number>` でIssueタイトルを取得
3. タイトルからslugを生成（小文字、スペースをハイフンに、記号削除）
4. mainブランチを最新に更新
5. `feature/<number>-<slug>` ブランチを作成してチェックアウト

## Example

```
/issue-start 4
```

実行結果:
- Issue #4 "Ethernetフレーム処理" を取得
- `git checkout main && git pull`
- `git checkout -b feature/4-ethernet-frame`
- 作業開始準備完了

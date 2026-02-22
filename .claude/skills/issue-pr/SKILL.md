# issue-pr

現在のブランチから Issue 番号を抽出し、PR を作成する skill。

## 引数

- `$ARGUMENTS` — なし（現在のブランチ名から自動取得）

## 手順

1. 現在のブランチ名を取得する (`git branch --show-current`)
2. ブランチ名から Issue 番号を抽出する（`issue/<NUM>-<SLUG>` 形式を期待）
3. `gh issue view <NUM> --json number,title,labels,body` で Issue 情報を取得する
4. コミットログを確認し、変更内容のサマリを生成する
5. PR テンプレート (`.github/pull_request_template.md`) に従い、以下を埋める:
   - **Summary**: コミットログベースの変更サマリ
   - **Related Issue**: `Closes #<NUM>`
   - **RFC Reference**: ユーザに記入を促す（コード内の `RFC-REF` コメントがあれば列挙）
   - **RFC Deviations**: コード内の `RFC-DEVIATION` コメントがあれば列挙。なければ「なし」
   - **Changes**: 変更ファイル一覧
   - **Testing**: チェックリスト
6. `gh pr create --base main --head issue/<NUM>-<SLUG>` で PR を作成する
7. CI ステータスを確認する（`gh pr checks` で待機）
8. CI pass なら `gh issue edit <NUM> --remove-label wip` で `wip` ラベルを削除する
9. PR URL を表示する

## RFC Reference 記入ガイド

PR 作成時にユーザに以下を案内する:

> PR テンプレートの「RFC Reference」欄に、この変更が依拠する RFC 節を記載してください。
> 該当なしの場合は「N/A」としてください。
> コード中に RFC-DEVIATION がある場合は「RFC Deviations」欄にも概要を記載してください。

## 注意

- ブランチが `issue/<NUM>-<SLUG>` 形式でない場合はエラーで中断する。
- CI が失敗した場合は `wip` ラベルを残し、失敗内容をユーザに案内する。

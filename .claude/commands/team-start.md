# Team Start

tmux セッション `ruster-team` を作成し、lead + worker (w1/w2/w3) の 4 ペイン構成を起動する。

## 手順

1. tmux セッション `ruster-team` が既に存在するか確認する。存在すればアタッチのみ行い終了する
2. tmux new-session で `ruster-team` セッションを作成する (最初のペインが lead)
3. 3 つの水平分割ペインを作成する (w1, w2, w3)
4. tiled レイアウトに切り替える
5. 各ペインのディレクトリをプロジェクトルートに設定する
6. セッションにアタッチする

## 実行例

```
/team-start
```

→ tmux セッション `ruster-team` が起動し、4 ペイン (lead / w1 / w2 / w3) が tiled レイアウトで表示される。

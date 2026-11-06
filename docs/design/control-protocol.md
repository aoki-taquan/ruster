# FEとCEの間のメッセージ形式

状態: 叩き台（2026-11-06）。[`fe-ce-split.md`](fe-ce-split.md)の「FEとCEの間のやり取り」を具体化する。

## 結論

| 層 | 採用するもの | 状態 |
|---|---|---|
| データの型と構造 | YANG | 標準 |
| エンコード | YANGのデータをCBORで表す方法（RFC 9254）と、名前の代わりの数値ID「SID」（RFC 9595） | RFC |
| 操作 | CORECONF（draft-ietf-core-comi-21）のFETCH、iPATCH、PUT、POST、Observeに合わせる | draft。下の「CORECONFとの違い」を除いて従う |
| 通り道 | Unix stream socketの上に、TCP向けのCoAPの枠組み（RFC 8323）を載せる | CORECONFからの逸脱 |
| パケットの受け渡し | 上とは別。固定ヘッダ付きのSOCK_SEQPACKET | 独自 |

YANGで「何を送れるか」が決まり、CEのどのプロセスも同じ形式を使う。文字列の項目名は使わない。

## 用語

- YANG: ネットワーク機器の設定と状態の型を書く言語。NETCONFやRESTCONFでも使う。
- CBOR: JSONに相当するバイナリ形式（RFC 8949）。
- SID: YANGの項目一つずつに割り当てる数値。メッセージの中では項目名の代わりにこれを使う。
- 表: FEが転送に使うデータ。この文書ではYANGのモジュール一つ、またはその一部にあたる。
- 書き手: ある表を書き換えてよいCEのプロセス。一つの表に書き手は一つ。

## 最初に扱う表

まず次の四つだけを作る。NAT、firewall、トンネルは、この四つが動いてから同じやり方で足す。

| 表 | YANGモジュール | SID | 書き手 | socket |
|---|---|---|---|---|
| インターフェース | `ietf-interfaces`（RFC 8343） | IANA割り当て済み（1500から100個） | 設定管理 | `/run/ruster/fe/config.sock` |
| アドレス、MTU | `ietf-ip`（RFC 8344）のipv4/ipv6のうちaddressとmtu | IANA割り当て済み（1600から100個） | 設定管理 | 同上 |
| 経路（FIB） | `ruster-fib`（独自） | 独自の範囲（下） | 経路デーモン | `/run/ruster/fe/route.sock` |
| 近隣 | `ruster-neighbor`（独自） | 独自の範囲（下） | 近隣デーモン | `/run/ruster/fe/neigh.sock` |

読み取り専用の`/run/ruster/fe/state.sock`では、全部の表と運用状態（カウンタ、リンク状態、FEが割り当てた
`if-index`）を読める。`show`はここを使う。

### 標準モジュールを使わない部分とその理由

- 経路: `ietf-routing`（RFC 8349）はRIB（経路の候補の集まり）を表すモデルで、FEが持つ「選ばれた経路だけの表」と
  合わない。経路の選択はCEの仕事なので、FEには選ばれた結果だけを書く`ruster-fib`を作る。
- 近隣: `ietf-ip`にも近隣のリストがあるが、インターフェースの中に入れ子になっている。そのため、
  インターフェースを書く設定管理と近隣デーモンの持ち物が同じ木の中で混ざる。書き手を一つにするため、
  インターフェース名で参照する平らなリストを`ruster-neighbor`として分ける。
- `ietf-ip`のうち近隣のリストとIPv6の自動設定の項目は、FEでは扱わない（書くと`4.00`で拒否する）。

### `ruster-fib`の形（案）

```yang
module ruster-fib {
  container fib {
    list route {
      key "destination-prefix";        // 例: "192.0.2.0/24"、"2001:db8::/32"
      choice action {
        case forward {
          list next-hop {              // 複数ならECMP
            key "outgoing-interface address";
            leaf outgoing-interface { type if:interface-ref; }
            leaf address { type inet:ip-address; }  // on-linkなら宛先自身を引く
          }
        }
        case local   { leaf local   { type empty; } }  // ルータ宛て
        case discard { leaf discard { type empty; } }  // 黙って捨てる
        case reject  { leaf reject  { type empty; } }  // ICMP Unreachableを返す
      }
    }
  }
}
```

VRFはまだ入れない。router as a serviceの段階で`fib`をVRFごとのリストにする。

### `ruster-neighbor`の形（案）

```yang
module ruster-neighbor {
  container neighbors {
    list neighbor {
      key "interface address";
      leaf interface { type if:interface-ref; }
      leaf address { type inet:ip-address; }
      leaf link-layer-address { type yang:phys-address; mandatory true; }
    }
  }
}
```

表にない次の転送先へのパケットが来たら、FEは解決依頼を通知として出す（下の「通知」）。

## 操作

CORECONFと同じく、FEには設定と状態をまとめた一つの「データストア」がある。各socketからは、
そのsocketの書き手が持つ表だけが書ける。

| 操作 | 使い方 |
|---|---|
| iPATCH | 表への追加、置き換え、削除。値をnullにすると削除。一回のiPATCHは全部反映されるか、まったく反映されないかのどちらか。FEの処理の切れ目で一度に反映し、反映してから`2.04`を返す |
| FETCH | 指定した項目を読む |
| GET | データストア全体を読む（`state.sock`） |
| PUT | その書き手の表全体を置き換える。送られなかったエントリは消える。小さい表の再同期に使う |
| POST | 操作（action）の呼び出し。大きい表の再同期の開始と終了に使う（下） |
| GET/FETCH + Observe | 通知の購読 |

### 例（CBORの診断表記、SIDは仮）

経路を一つ足し、一つ消すiPATCH:

```
{ [60010, "192.0.2.0/24"]: { 3: [ { 1: "wan0", 2: "203.0.113.1" } ] } }
{ [60010, "198.51.100.0/24"]: null }
```

`60010`は`route`リストのSID、中の`3`、`1`、`2`はRFC 9254の差分SID（親のSIDからの差）。

### 大きい表の再同期

経路デーモンが再起動すると、BGPのフルルート（約100万経路）を送り直すことがある。一回のメッセージには
収まらないので、次の手順にする。

1. POST `resync-begin`: FEはその書き手の全エントリに「未確認」の印を付ける。転送は今の表のまま続く。
2. iPATCHを何回でも送る。送られたエントリは印が消える。
3. POST `resync-end`: 印が残ったエントリを消す。

途中で接続が切れたら、印は付いたまま表は残る。次の接続でもう一度`resync-begin`からやり直す。

### 通知

FEは次の通知を出す。CEはObserveで購読する。

- 近隣の解決依頼（インターフェース、次の転送先のアドレス）。流量制限付き。
- リンク状態の変化。
- 再同期中の書き手が切断した、などFE側で起きた異常。

通知は溜めすぎない。CORECONFのとおり、取りこぼしと重複はありうる前提でCEを作る。
解決依頼は、取りこぼしても次のパケットでまた出る。

### エラー

CORECONFの`ietf-coreconf:error`（`error-tag`、`error-app-tag`、`error-data-node`、`error-message`）で返す。

- 型や範囲の違反: `4.00`。
- 自分の表以外への書き込み: `4.03`（CoAP標準のコード。CORECONFの表には無い）。
- エラーになったリクエストは表を一切変えない。

表をまたぐ参照（例: 経路が指すインターフェースがまだ無い）はエラーにしない。そのエントリを無効として
保持し、運用状態に理由を出す。参照先ができたら有効になる。

## 通り道

- Unix stream socketを書き手ごとに分け、ファイルの権限で誰が書けるかを決める。
- 枠組みはTCP向けのCoAP（RFC 8323）。ACKや再送が要らず、最大メッセージ長を最初に交換できる。
  初期値は16 MiB。
- 後でFEとCEを別マシンに置くときは、同じ枠組みをTCP（とTLS）に載せる。

## パケットの受け渡し

ARP、ND、DHCP、DHCPv6、PPPoEのフレームの受け渡しは、上のメッセージ形式を使わない。CBORで包む意味が
無く、量も多いため。

- プロトコルごとにSOCK_SEQPACKETを分ける（例: `/run/ruster/fe/punt/arp-nd.sock`）。
- 1メッセージ = 固定ヘッダ + フレーム一つ。

```
version   u8    = 1
kind      u8    受け取り(1) / 送り出し(2)
reason    u16   受け取った理由（プロトコル、解決依頼への応答など）
if_index  u32   FEのif-index（state.sockのietf-interfacesで名前と対応）
length    u32   フレームの長さ
frame     ...
```

- FEは種類ごとに流量の上限を付け、溢れた分は捨てて数える（[`fe-ce-split.md`](fe-ce-split.md)の
  「ルータ宛て通信の保護」）。
- ルータ宛てのTCP/UDPはここを通らず、TUNでkernelへ渡す。

## SIDの割り当て

- 標準モジュールはIANAが割り当てたSIDを使う（`ietf-interfaces`は1500から、`ietf-ip`は1600から）。
- 独自モジュールは、開発中は実験用の範囲（60000〜99999）を使い、`.sid`ファイルを`unpublished`、
  各項目を`unstable`にする。この範囲は運用で使ってはいけない決まりなので、常用の前に移す。
- 常用の前に、IANAのPrivate Enterprise Number（無料）を取り、RFC 9997でPENから決まる範囲へ移す。
- `.sid`ファイル（RFC 9595のJSON形式）をrepositoryに置いて正本にする。Rust側のSIDの定数は手で書き、
  `.sid`ファイルと一致するかをテストで確かめる。YANGからRustのコードを生成する仕組みは作らない。

## 実装の置き場所

- 新しいcrate一つに、CBORの読み書き、CoAPの枠組み、SIDの定数、パケット受け渡しのヘッダを入れる。
  FEとCEの全プロセスがこれを使う。
- CBORは使う範囲（整数、バイト列、文字列、配列、マップ、null、真偽値）が小さいので自作する。
  data-planeのcrateに外部依存を入れない今の方針と合う。
- FEはこのcrateを制御用のthreadだけで使い、転送の処理経路には入れない。

## CORECONFとの違い

draft-ietf-core-comi-21に対して、次の点で違う。draftが変わったら見直す。

| 項目 | CORECONF | ruster | 理由 |
|---|---|---|---|
| 通り道 | CoAP over UDP（DTLSまたはOSCORE） | CoAPのTCP向け枠組みをUnix socketに載せる | 同じ箱の中で使う。順序と信頼性はsocketが保証する |
| iPATCHの一括性 | 明記されていない | 一回のiPATCHは全部反映か全部取り消し | 「開始 → 追加/削除 → 確定」の要件 |
| 無いものの削除 | 明記されていない | 成功として扱う | 同じ操作を繰り返しても同じ結果にする |
| 書き込みの範囲 | 一つのデータストア全体 | socketごとに書ける表を限る | 一つの表に書き手は一つ |
| 大きい表の再同期 | 定義なし | `resync-begin` / `resync-end`の操作 | 100万経路を一回で送れない |
| 権限違反 | エラーコードの表に無い | `4.03` | CoAP標準のコードを使う |

## 未決事項

- FETCHの応答でリストのキーが省かれる（CORECONFの仕様）。CE側で扱いにくければ、`state.sock`だけ
  キー付きで返すかを決める。
- 1経路あたりの大きさと、100万経路の再同期にかかる時間の見積もりと実測。
- IPv6の近隣（ND）と、PPPoEのセッションをFEの表としてどう表すか。
- NAT（`ietf-nat`、RFC 8512）とfirewall（`ietf-access-control-list`、RFC 8519）を標準モデルのまま使えるか。
- PENを取るかどうか（取るならowner名義）。
- 今のTOML設定を、設定管理（CLI）がこのメッセージへ変換する形に移す手順。

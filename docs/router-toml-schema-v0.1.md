# router.toml スキーマ定義（v0.1）

## 1. 目的

この文書は `ruster` v0.1 の `router.toml` 最小キーセットを定義する。  
対象は「自宅ラボで家庭用ルータとして使える」構成で、L2/L3転送と NAT を成立させることを主眼とする。

## 2. 設計ルール

- 暗黙デフォルトは禁止する。
- 本文書にある必須キーはすべて記載する。
- `validate -> plan -> apply` で検証可能な値のみ受け入れる。
- 未知キーはエラーとする（v0.1 は strict）。

## 3. トップレベル構造

`router.toml` は以下のトップレベルセクションで構成する。

- `[meta]`
- `[dataplane]`
- `[[interfaces]]`
- `[l2]`
- `[routing]`
- `[nat]`
- `[firewall]`

## 4. セクション別必須キー

### 4.1 `[meta]`

- `schema`: string。固定値 `ruster/v0.1`
- `hostname`: string。ノード名

### 4.2 `[dataplane]`

- `backend`: string。v0.1 は `dpdk` 固定
- `lcore_list`: string。例: `"0-3"`
- `memory_mb`: integer。DPDK向けメモリ（MB）
- `rx_queue_size`: integer
- `tx_queue_size`: integer

### 4.3 `[[interfaces]]`

各インタフェースで以下を必須とする。

- `name`: string。一意識別子（例: `wan0`, `lan0`）
- `port_id`: integer。DPDKポートID
- `role`: string。`wan` または `lan`
- `admin_up`: bool
- `mtu`: integer
- `mac`: string。MACアドレス表記
- `ipv4_addrs`: array(string)。CIDR形式
- `zone`: string。`wan` または `lan`（FW/NAT判定用）
- `l2_domain`: string。所属L2ドメイン名

### 4.4 `[l2]`

- `mac_table_max_entries`: integer
- `mac_aging_sec`: integer
- `arp_table_max_entries`: integer
- `arp_timeout_sec`: integer
- `bridge_domains`: array(table)

`bridge_domains` 要素の必須キー:

- `name`: string。L2ドメイン名
- `members`: array(string)。所属IF名

### 4.5 `[routing]`

- `ipv4_static_routes`: array(table)

`ipv4_static_routes` 要素の必須キー:

- `prefix`: string。CIDR
- `next_hop`: string。IPv4アドレス
- `out_if`: string。送信IF名
- `metric`: integer

### 4.6 `[nat]`

- `enabled`: bool
- `mode`: string。v0.1 は `napt44` 固定
- `external_if`: string。通常 `wan0`
- `hairpin`: bool
- `session_table_max_entries`: integer
- `tcp_established_timeout_sec`: integer
- `tcp_transitory_timeout_sec`: integer
- `udp_timeout_sec`: integer
- `icmp_timeout_sec`: integer
- `port_forwards`: array(table)。要素0件でも必須（空配列可）

`port_forwards` 要素の必須キー:

- `name`: string
- `proto`: string。`tcp` / `udp`
- `external_port`: integer
- `internal_addr`: string。IPv4
- `internal_port`: integer

### 4.7 `[firewall]`

- `enabled`: bool
- `default_input`: string。`accept` / `drop`
- `default_forward`: string。`accept` / `drop`
- `default_output`: string。`accept` / `drop`
- `allow_established_related`: bool
- `rules`: array(table)。要素0件でも必須（空配列可）

`rules` 要素の必須キー:

- `name`: string
- `chain`: string。`input` / `forward` / `output`
- `action`: string。`accept` / `drop`
- `proto`: string。`any` / `tcp` / `udp` / `icmp`
- `src_zone`: string。`wan` / `lan` / `any`
- `dst_zone`: string。`wan` / `lan` / `any`
- `state`: array(string)。`new` / `established` / `related`

## 5. 最小バリデーション規則

- `interfaces.name` は一意であること。
- `interfaces.port_id` は一意であること。
- `l2.bridge_domains[*].members` のIFはすべて `interfaces.name` に存在すること。
- `routing.ipv4_static_routes[*].out_if` は存在するIF名であること。
- `nat.external_if` は `role = "wan"` のIFであること。
- `nat.enabled = true` の場合、`firewall.enabled = true` を必須とする。
- `firewall.rules[*].state` は空配列禁止。

## 6. 参考

- サンプル設定: `router.toml.example`

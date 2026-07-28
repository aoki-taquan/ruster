# Prototype v0.1

2026年3月時点の広範なarchitecture prototypeはGit tag
[`prototype-v0.1`](https://github.com/aoki-taquan/ruster/tree/prototype-v0.1)に保存されています。

旧版にはL2/L3、ARP、NAT、firewall、IPv6、routing protocol、SRv6などの探索的実装が
ありますが、実DPDK RX/TXを持たず、hot pathの所有/同期modelもv0.2とは異なります。
そのためactive treeでは延命せず、ゼロベースで実装します。

旧版から新コードへRust実装をcopyしません。再利用できるものはRFC根拠、black-boxの
packet入力と期待値、validate/plan/applyの要件、外部観測を含むE2Eの考え方です。

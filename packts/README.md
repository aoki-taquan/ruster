## 考慮事項
### Ethernet
ジャンボフレームには対応していない．

checkcommand
```
$ cargo hack check --feature-powerset   --include-features arp,ethernet,ipv4,ipv6,vlan
```

### IPv4
```
$ cargo hack check --feature-powerset   --include-features icmp,tcp,udp,ipv4,ipv4_options
```

ipv4_optionsはEnd of Options Listのみ対応しており，ほぼ使用できないといっても過言ではない

### Ip

### ARP
解決する上位プロトコルがIPv4であるとの想定であり，IPv4以外の場合では動作しないことがある．

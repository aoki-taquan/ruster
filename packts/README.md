## 考慮事項
### Ethernet
ジャンボフレームには対応していない．

checkcommand
```
$ cargo hack check --feature-powerset   --include-features arp,ethernet,ipv4,ipv6,vlan
```

### ARP
解決する上位プロトコルがIPv4であるとの想定であり，IPv4以外の場合では動作しないことがある．

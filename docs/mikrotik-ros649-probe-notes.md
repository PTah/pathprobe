# MikroTik RouterOS 6.49.19 — заметки для проб (без автоприменения)

Фаза 1 pathprobe **не импортирует** `.rsc` и не меняет роутер. Ниже — ручные ориентиры, если echo крутится на хосте за рабочим MikroTik.

## Цели

- Открыть на WAN только нужные probe-порты к **своему** внутреннему хосту.
- Не светить управление (Winbox/SSH) без необходимости.

## Пример dst-nat (WAN → внутренний Ubuntu/хост)

Подставьте свои интерфейс WAN, IP и порты:

```rsc
/ip firewall nat
add chain=dstnat in-interface=ether1 protocol=tcp dst-port=8443 \
  action=dst-nat to-addresses=10.10.10.50 to-ports=8443 \
  comment="pathprobe-tcp-echo"
add chain=dstnat in-interface=ether1 protocol=udp dst-port=51820 \
  action=dst-nat to-addresses=10.10.10.50 to-ports=51820 \
  comment="pathprobe-udp-echo"
add chain=dstnat in-interface=ether1 protocol=tcp dst-port=443 \
  action=dst-nat to-addresses=10.10.10.50 to-ports=443 \
  comment="pathprobe-tls-echo"
```

Filter (если input/forward режет):

```rsc
/ip firewall filter
add chain=forward connection-nat-state=dstnat action=accept \
  comment="pathprobe-allow-dstnat"
```

## DNS для пробы подмены A

Если тестируете DNS-слой — резолвер должен быть **ваш** (на MikroTik `/ip dns` или отдельный сервис). В `config.yaml` укажите `expected_a` для имён, которые вы сами задаёте. Чужие домены не использовать.

## Связь с гайдами

Офисные туннели GRE/IPsec/OSPF и IKEv2 EAP — в `Answer.and.other.shit/guides/mikrotik/`. Pathprobe фаза 2 будет опираться на те же идеи (strongSwan, IPsec, WG), но для линка **home Ubuntu ↔ work MikroTik**.

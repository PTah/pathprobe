# Архитектура фазы 2 (заглушка)

Фаза 1: диагностика и классификация. Фаза 2 (ещё не реализована): защищённый канал.

## Топология

```
[home Ubuntu router]  ----ISP/DPI----  [work MikroTik ROS 6.49.19]
        |                                      |
   pathprobe CLI                          dst-nat / IPsec / WG
   (диагностика)                          peer endpoint
```

Оркестратор (позже): ПК или сам home Ubuntu — SSH к обоим концам, генерация конфигов, **не** трогать чужие ресурсы.

## Профили (из `profiles/registry.yaml`)

| ID | Home (Ubuntu) | Work (MikroTik 6.49) |
|----|---------------|----------------------|
| `ikev2_ipsec` | strongSwan | `/ip ipsec` IKEv2 |
| `gre_ipsec` | gre + xfrm/strongSwan | GRE/IPIP + IPsec (как в гайдах) |
| `wireguard` | `wg-quick` | WireGuard package / отдельный peer-хост |
| `openvpn_tcp443` | OpenVPN client TCP/443 | OpenVPN server или хост за NAT |

## Планируемый поток

1. `pathprobe diagnose` → JSON/MD.
2. `pathprobe recommend` → выбор профиля по классификации.
3. `pathprobe render` → файлы конфигов (без apply).
4. `pathprobe apply --dry-run` / `apply` → SSH + import (с бэкапом).
5. Keepalive + failover на резервный профиль при деградации.

На текущий момент шаги 2–5 **не реализованы**; registry и этот документ — контракт для следующей итерации.

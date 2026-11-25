# Связь с CircumVolve (ccs26-circumvolve)

Pathprobe **не** запускает OpenEvolve и **не** эволюционирует стратегии обхода. Берётся только таксономия слоёв и идея «матрица доступности → класс причины».

| Слой pathprobe | Сценарий CircumVolve | Что измеряем |
|----------------|----------------------|--------------|
| DNS | `DNS-Blocking` | NXDOMAIN / SERVFAIL / подмена A / timeout |
| TCP | портовая часть HTTP / TCP manipulation | open / RST / timeout / refused |
| TLS | `TLS-SNI-Blocking` | handshake OK / drop ClientHello / RST after CH |
| UDP | QUIC / IKE / WG-подобные порты | echo OK / timeout / ICMP unreach |
| MTU | сопутствующий фактор | DF blackhole / ограниченный path MTU |

Классификатор (`pathprobe/diagnose/classify.py`) выдаёт `circumvolve_analogues` и **рекомендации профилей** без apply.

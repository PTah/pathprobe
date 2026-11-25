#!/usr/bin/env python3
"""UDP echo, совместимый с pathprobe.diagnose.udp (маркер PATHPROBE1).

  python3 echo/udp_echo.py --port 51820
"""

from __future__ import annotations

import argparse
import socket

MAGIC = b"PATHPROBE1"


def main() -> None:
    p = argparse.ArgumentParser(description="UDP echo (pathprobe)")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=51820)
    args = p.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(f"UDP echo слушает {args.bind}:{args.port}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        # Отвечаем тем же payload (или MAGIC+echo)
        if data.startswith(MAGIC) or data == MAGIC:
            sock.sendto(data, addr)
        else:
            sock.sendto(MAGIC + data[:64], addr)


if __name__ == "__main__":
    main()

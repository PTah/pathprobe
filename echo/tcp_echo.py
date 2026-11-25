#!/usr/bin/env python3
"""Простой TCP echo для дальнего конца (своя инфраструктура).

Запуск на хосте за MikroTik или на VPS:
  python3 echo/tcp_echo.py --port 8443
"""

from __future__ import annotations

import argparse
import socket
import threading


def handle(conn: socket.socket, addr: tuple) -> None:
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    finally:
        conn.close()


def main() -> None:
    p = argparse.ArgumentParser(description="TCP echo (pathprobe)")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    args = p.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(32)
    print(f"TCP echo слушает {args.bind}:{args.port}", flush=True)
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()

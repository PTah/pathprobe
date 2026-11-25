#!/usr/bin/env python3
"""Минимальный TLS-сервер для пробы SNI (self-signed).

Генерация сертификата (пример):
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \\
    -subj "/CN=vpn.work.example"

  python3 echo/tls_echo.py --port 443 --cert cert.pem --key key.pem
"""

from __future__ import annotations

import argparse
import socket
import ssl
import threading


def handle(conn: ssl.SSLSocket, addr: tuple) -> None:
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    p = argparse.ArgumentParser(description="TLS echo (pathprobe)")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    args = p.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind((args.bind, args.port))
    raw.listen(32)
    print(f"TLS echo слушает {args.bind}:{args.port}", flush=True)
    while True:
        conn, addr = raw.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as exc:
            print(f"SSL ошибка от {addr}: {exc}", flush=True)
            conn.close()
            continue
        threading.Thread(target=handle, args=(tls, addr), daemon=True).start()


if __name__ == "__main__":
    main()

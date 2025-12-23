#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import threading


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def _handle_connection(client: socket.socket, *, vsock_cid: int, vsock_port: int) -> None:
    try:
        upstream = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        upstream.settimeout(5)
        upstream.connect((vsock_cid, vsock_port))
    except Exception:
        try:
            client.close()
        finally:
            return

    client.settimeout(None)
    upstream.settimeout(None)

    thread_in = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
    thread_out = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
    thread_in.start()
    thread_out.start()
    thread_in.join()
    thread_out.join()

    try:
        client.close()
    except Exception:
        pass
    try:
        upstream.close()
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP↔vsock bridge for Nitro Enclaves")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=5001)
    ap.add_argument("--vsock-cid", type=int, required=True)
    ap.add_argument("--vsock-port", type=int, default=5000)
    args = ap.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.listen_host, args.listen_port))
    server.listen(128)

    print(
        f"[vsock-bridge] tcp://{args.listen_host}:{args.listen_port} -> vsock://{args.vsock_cid}:{args.vsock_port}"
    )

    while True:
        client, _ = server.accept()
        threading.Thread(
            target=_handle_connection,
            args=(client,),
            kwargs={"vsock_cid": args.vsock_cid, "vsock_port": args.vsock_port},
            daemon=True,
        ).start()


if __name__ == "__main__":
    raise SystemExit(main())

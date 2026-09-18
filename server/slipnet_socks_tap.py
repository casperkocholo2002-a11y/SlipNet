#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


parser = argparse.ArgumentParser()
parser.add_argument("--listen-port", type=int, required=True)
parser.add_argument("--protocol", required=True)
parser.add_argument("--stats", required=True)
parser.add_argument("--upstream-host", default="127.0.0.1")
parser.add_argument("--upstream-port", type=int, default=1080)
args = parser.parse_args()


PERSIST_DIR = "/var/lib/slipnet-monitor"
os.makedirs(PERSIST_DIR, mode=0o700, exist_ok=True)
try:
    os.chmod(PERSIST_DIR, 0o700)
except OSError:
    pass
PERSIST_PATH = os.path.join(PERSIST_DIR, f"tap-{args.protocol.lower()}.json")


def _load_previous_state():
    # First migration preserves counters already accumulated in /run. Later
    # restarts prefer the durable copy under /var/lib.
    for path in (PERSIST_PATH, args.stats):
        try:
            with open(path, "r") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                return raw
        except Exception:
            pass
    return {}


_previous = _load_previous_state()
state = {
    "protocol": args.protocol,
    "listen_port": args.listen_port,
    "upstream": f"{args.upstream_host}:{args.upstream_port}",
    "started_at": now(),
    "users": {}
}

for _name, _old in _previous.get("users", {}).items():
    if not isinstance(_old, dict):
        continue
    state["users"][_name] = {
        "protocol": args.protocol,
        "online": False,
        "active_connections": 0,
        "connected_since": None,
        "tx_bytes": int(_old.get("tx_bytes", 0) or 0),
        "rx_bytes": int(_old.get("rx_bytes", 0) or 0),
        "total_bytes": int(_old.get("total_bytes", 0) or 0),
        "sessions": int(_old.get("sessions", 0) or 0),
        "last_seen": _old.get("last_seen"),
        "last_disconnected": _old.get("last_disconnected"),
        "last_destination": _old.get("last_destination"),
    }


def get_user(name):
    if name not in state["users"]:
        state["users"][name] = {
            "protocol": args.protocol,
            "online": False,
            "active_connections": 0,
            "connected_since": None,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "total_bytes": 0,
            "sessions": 0,
            "last_seen": None,
            "last_disconnected": None,
            "last_destination": None
        }
    return state["users"][name]


def _atomic_save(path, mode=0o600):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def save_stats():
    for u in state["users"].values():
        u["total_bytes"] = u["tx_bytes"] + u["rx_bytes"]

    _atomic_save(args.stats, 0o600)
    _atomic_save(PERSIST_PATH, 0o600)


async def periodic_save():
    while True:
        save_stats()
        await asyncio.sleep(1)


async def read_addr(reader, atyp):
    if atyp == 0x01:
        raw = await reader.readexactly(4)
        text = ".".join(str(x) for x in raw)
        return raw, text

    if atyp == 0x03:
        ln = await reader.readexactly(1)
        name = await reader.readexactly(ln[0])
        raw = ln + name
        return raw, name.decode("utf-8", "replace")

    if atyp == 0x04:
        raw = await reader.readexactly(16)
        groups = []
        for i in range(0, 16, 2):
            groups.append(f"{(raw[i] << 8) | raw[i+1]:x}")
        return raw, ":".join(groups)

    raise ValueError("Unsupported SOCKS address type")


async def relay(reader, writer, username, direction):
    user = get_user(username)

    try:
        while True:
            chunk = await reader.read(65536)

            if not chunk:
                break

            writer.write(chunk)
            await writer.drain()

            if direction == "tx":
                user["tx_bytes"] += len(chunk)
            else:
                user["rx_bytes"] += len(chunk)

            user["last_seen"] = now()

    except Exception:
        pass

    try:
        if writer.can_write_eof():
            writer.write_eof()
    except Exception:
        pass


async def handle_client(client_reader, client_writer):
    upstream_reader = None
    upstream_writer = None

    username = "UNKNOWN"
    registered = False

    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            args.upstream_host,
            args.upstream_port
        )

        # SOCKS5 greeting
        greeting = await client_reader.readexactly(2)

        if greeting[0] != 0x05:
            return

        methods = await client_reader.readexactly(greeting[1])

        upstream_writer.write(greeting + methods)
        await upstream_writer.drain()

        method_reply = await upstream_reader.readexactly(2)

        client_writer.write(method_reply)
        await client_writer.drain()

        selected_method = method_reply[1]

        if selected_method == 0x02:
            # RFC1929 username/password authentication
            auth_head = await client_reader.readexactly(2)

            if auth_head[0] != 0x01:
                return

            username_raw = await client_reader.readexactly(auth_head[1])
            username = username_raw.decode("utf-8", "replace")

            plen_raw = await client_reader.readexactly(1)
            password_raw = await client_reader.readexactly(plen_raw[0])

            auth_packet = (
                auth_head +
                username_raw +
                plen_raw +
                password_raw
            )

            upstream_writer.write(auth_packet)
            await upstream_writer.drain()

            auth_reply = await upstream_reader.readexactly(2)

            client_writer.write(auth_reply)
            await client_writer.drain()

            if auth_reply[1] != 0x00:
                return

        elif selected_method == 0x00:
            username = "NO_AUTH"

        else:
            return

        # SOCKS CONNECT request
        req_head = await client_reader.readexactly(4)

        if req_head[0] != 0x05:
            return

        atyp = req_head[3]

        addr_raw, destination = await read_addr(client_reader, atyp)
        port_raw = await client_reader.readexactly(2)

        port = (port_raw[0] << 8) | port_raw[1]

        upstream_writer.write(req_head + addr_raw + port_raw)
        await upstream_writer.drain()

        # SOCKS CONNECT response
        reply_head = await upstream_reader.readexactly(4)
        reply_addr_raw, _ = await read_addr(upstream_reader, reply_head[3])
        reply_port_raw = await upstream_reader.readexactly(2)

        client_writer.write(
            reply_head +
            reply_addr_raw +
            reply_port_raw
        )
        await client_writer.drain()

        if reply_head[1] != 0x00:
            return

        user = get_user(username)

        if user["active_connections"] == 0:
            user["connected_since"] = now()

        user["online"] = True
        user["active_connections"] += 1
        user["sessions"] += 1
        user["last_seen"] = now()
        user["last_destination"] = f"{destination}:{port}"

        registered = True
        save_stats()

        await asyncio.gather(
            relay(
                client_reader,
                upstream_writer,
                username,
                "tx"
            ),
            relay(
                upstream_reader,
                client_writer,
                username,
                "rx"
            ),
            return_exceptions=True
        )

    except (
        asyncio.IncompleteReadError,
        ConnectionError,
        OSError,
        ValueError
    ):
        pass

    finally:
        if registered:
            user = get_user(username)

            user["active_connections"] = max(
                0,
                user["active_connections"] - 1
            )

            user["last_seen"] = now()

            if user["active_connections"] == 0:
                user["online"] = False
                user["last_disconnected"] = now()
                user["connected_since"] = None

            save_stats()

        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass

        if upstream_writer:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass


async def main():
    server = await asyncio.start_server(
        handle_client,
        "127.0.0.1",
        args.listen_port
    )

    print(
        f"{args.protocol} SOCKS accounting tap "
        f"127.0.0.1:{args.listen_port} -> "
        f"{args.upstream_host}:{args.upstream_port}",
        flush=True
    )

    save_stats()
    asyncio.create_task(periodic_save())

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())

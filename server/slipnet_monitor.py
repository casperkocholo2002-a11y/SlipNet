#!/usr/bin/env python3
"""
SlipNet User Monitor - Web Dashboard
Run: python3 slipnet_monitor.py
Then open: http://YOUR_SERVER_IP:8080
"""

import subprocess
import os
import time
import json
import vless_admin
import re
import base64
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PASSWORD = os.environ.get("SLIPNET_MONITOR_PASSWORD", "").strip()
if not PASSWORD:
    raise RuntimeError("SLIPNET_MONITOR_PASSWORD is required")

def detect_service(ip, port):
    port = str(port)
    octets = ip.split('.')
    if len(octets) < 2: return "Unknown"
    o1, o2 = octets[0], octets[1] if len(octets) > 1 else "0"
    if o1 == "149" and o2 == "154": return "Telegram"
    if o1 == "91" and o2 == "108": return "Telegram"
    if o1 == "57" and o2 == "144":
        return "WhatsApp" if port == "5222" else "Instagram"
    if o1 in ("157","31","66","69","173","179"):
        return "WhatsApp" if port == "5222" else "Instagram/Facebook"
    if o1 == "185" and o2 == "60": return "WhatsApp"
    if o1 in ("142","172","216","74","64","66","173","192","108"):
        if port == "5228": return "Google Push"
        if port == "443": return "YouTube/Gmail"
        return "Google"
    if ip in ("8.8.8.8","8.8.4.4"): return "Google DNS"
    if ip in ("1.1.1.1","1.0.0.1"): return "Cloudflare DNS"
    if o1 == "104": return "Cloudflare CDN"
    if o1 in ("13","18","52","54","34"): return "Amazon AWS"
    if o1 == "17": return "Apple"
    if o1 in ("20","40"): return "Microsoft"
    if o1 == "10" or (o1 == "192" and o2 == "168"): return "⚠ Private IP"
    return "Unknown"

def format_bytes(b):
    b = int(b or 0)
    if b >= 1048576: return f"{b/1048576:.1f} MB"
    if b >= 1024: return f"{b/1024:.1f} KB"
    return f"{b} B"

def get_connected_since(pid):
    try:
        result = subprocess.run(['ps', '-o', 'lstart=', '-p', pid], capture_output=True, text=True)
        lstart = result.stdout.strip()
        if not lstart: return None, None
        dt = datetime.strptime(lstart, "%a %b %d %H:%M:%S %Y")
        now = datetime.now()
        diff = now - dt
        total_secs = int(diff.total_seconds())
        hours = total_secs // 3600
        minutes = (total_secs % 3600) // 60
        if hours > 0:
            duration = f"{hours}h {minutes}m"
        else:
            duration = f"{minutes}m"
        return dt.strftime("%H:%M:%S"), duration
    except:
        return None, None

def get_active_users():
    try:
        result = subprocess.run(['ss', '-tnp'], capture_output=True, text=True)
        users = {}
        for line in result.stdout.splitlines():
            if ':9011' not in line: continue
            pid_match = re.search(r'pid=(\d+)', line)
            peer_match = re.search(r'\S+:9011\s+(\S+)', line)
            if not pid_match or not peer_match: continue
            pid = pid_match.group(1)
            peer_ip = peer_match.group(1).rsplit(':', 1)[0]
            try:
                user_result = subprocess.run(['ps', '-o', 'user=', '-p', pid], capture_output=True, text=True)
                username = user_result.stdout.strip()
            except:
                username = "unknown"
            if username and username not in ("root", "sshd", "nobody"):
                if username not in users:
                    since, duration = get_connected_since(pid)
                    users[username] = {"pids": [], "ips": [], "since": since, "duration": duration}
                if pid not in users[username]["pids"]:
                    users[username]["pids"].append(pid)
                if peer_ip not in users[username]["ips"]:
                    users[username]["ips"].append(peer_ip)
        return users
    except:
        return {}

def get_connections_for_pid(pid):
    try:
        result = subprocess.run(['ss', '-tinp'], capture_output=True, text=True)
        connections = []
        lines = result.stdout.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if f'pid={pid}' in line and ':9011' not in line:
                peer_match = re.search(r'\S+:\d+\s+(\S+:\d+)', line)
                state_match = re.match(r'(\S+)', line)
                sent, recv = 0, 0
                if i + 1 < len(lines):
                    detail = lines[i + 1]
                    sm = re.search(r'bytes_sent:(\d+)', detail)
                    rm = re.search(r'bytes_received:(\d+)', detail)
                    if sm: sent = int(sm.group(1))
                    if rm: recv = int(rm.group(1))
                if peer_match:
                    peer = peer_match.group(1)
                    parts = peer.rsplit(':', 1)
                    ip = parts[0]
                    port = parts[1] if len(parts) > 1 else "0"
                    total = sent + recv
                    activity = "Background" if total < 5000 else ("Normal" if total < 500000 else "ACTIVE")
                    connections.append({
                        "peer": peer, "ip": ip, "port": port,
                        "service": detect_service(ip, port),
                        "sent": sent, "recv": recv,
                        "sent_f": format_bytes(sent),
                        "recv_f": format_bytes(recv),
                        "total": total, "activity": activity,
                        "state": state_match.group(1) if state_match else ""
                    })
            i += 1
        return sorted(connections, key=lambda x: x['total'], reverse=True)
    except:
        return []

def get_history(username, limit=30):
    try:
        result = subprocess.run(
            ['grep', '-E', f'Accepted password for {username} |session closed for user {username}$', '/var/log/auth.log'],
            capture_output=True, text=True
        )
        events = []
        for line in result.stdout.splitlines():
            time_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            if not time_match: continue
            t = time_match.group(1)
            if 'Accepted' in line:
                ip_match = re.search(r'from (\S+)', line)
                events.append({"time": t, "type": "connect", "ip": ip_match.group(1) if ip_match else ""})
            else:
                events.append({"time": t, "type": "disconnect", "ip": ""})
        return events[-limit:]
    except:
        return []

def disconnect_user(username):
    try:
        result = subprocess.run(['ss', '-tnp'], capture_output=True, text=True)
        ips = []
        for line in result.stdout.splitlines():
            if ':9011' not in line: continue
            pid_match = re.search(r'pid=(\d+)', line)
            peer_match = re.search(r'\S+:9011\s+(\S+)', line)
            if not pid_match or not peer_match: continue
            pid = pid_match.group(1)
            user_result = subprocess.run(['ps', '-o', 'user=', '-p', pid], capture_output=True, text=True)
            if user_result.stdout.strip().lower() == username.lower():
                peer_ip = peer_match.group(1).rsplit(':', 1)[0]
                ips.append(peer_ip)
        for ip in set(ips):
            subprocess.run(['ss', '-K', 'dst', ip], capture_output=True)
        return {"success": True, "message": f"Disconnected {username}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

TUNNEL_STATS = [
    ("/run/slipnet-tap-slipstream.json", "SLIPSTREAM"),
    ("/run/slipnet-tap-noizdns.json", "NOIZDNS"),
]

def duration_from_iso(value):
    if not value:
        return None
    try:
        started = datetime.fromisoformat(value.replace("Z", "+00:00"))
        now = datetime.now(started.tzinfo)
        seconds = max(0, int((now - started).total_seconds()))
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except:
        return None

def read_tunnel_stats():
    results = []

    for filename, protocol in TUNNEL_STATS:
        try:
            with open(filename, "r") as f:
                raw = json.load(f)
        except:
            continue

        for username, info in raw.get("users", {}).items():
            sent = int(info.get("tx_bytes", 0) or 0)
            recv = int(info.get("rx_bytes", 0) or 0)
            total = sent + recv
            active_connections = int(info.get("active_connections", 0) or 0)
            destination = info.get("last_destination") or "Tunnel"

            if ":" in destination:
                ip, port = destination.rsplit(":", 1)
            else:
                ip, port = destination, "0"

            results.append({
                "username": username,
                "protocol": protocol,
                "online": bool(info.get("online")),
                "connected_since_iso": info.get("connected_since"),
                "duration": duration_from_iso(info.get("connected_since")),
                "active_connections": active_connections,
                "sessions": int(info.get("sessions", 0) or 0),
                "last_seen": info.get("last_seen"),
                "last_destination": destination,
                "connection": {
                    "peer": destination,
                    "ip": ip,
                    "port": port,
                    "service": f"{protocol} Tunnel",
                    "protocol": protocol,
                    "sent": sent,
                    "recv": recv,
                    "sent_f": format_bytes(sent),
                    "recv_f": format_bytes(recv),
                    "total": total,
                    "activity": "ACTIVE" if active_connections else "Background",
                    "state": "TUNNEL",
                    "tunnel_connections": active_connections,
                    "sessions": int(info.get("sessions", 0) or 0),
                }
            })

    return results


VLESS_STATE = {
    "last_total": 0,
    "last_change": 0,
}

def read_vless_stats():
    """
    Read Xray Stats API for the working VLESS/WS user 'slipnet'.
    No UUID/path/credentials are exposed.
    """
    try:
        proc = subprocess.run(
            [
                "/usr/local/bin/xray",
                "api",
                "statsquery",
                "--server=127.0.0.1:10085",
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )

        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        raw = json.loads(proc.stdout)
        stats = {}

        for item in raw.get("stat", []):
            name = item.get("name", "")
            try:
                value = int(item.get("value", 0) or 0)
            except:
                value = 0
            stats[name] = value

        uplink = stats.get(
            "user>>>elahe>>>traffic>>>uplink", 0
        )
        downlink = stats.get(
            "user>>>elahe>>>traffic>>>downlink", 0
        )

        total = uplink + downlink

        online_key = "user>>>elahe>>>online"
        has_online_stat = online_key in stats
        online_value = stats.get(online_key, 0)

        now = time.time()

        # Keep a fallback activity detector in case this Xray build
        # does not return the online counter in statsquery output.
        if total != VLESS_STATE["last_total"]:
            VLESS_STATE["last_total"] = total
            VLESS_STATE["last_change"] = now

        if has_online_stat:
            online = online_value > 0
        else:
            online = (
                total > 0
                and VLESS_STATE["last_change"] > 0
                and now - VLESS_STATE["last_change"] <= 30
            )

        if VLESS_STATE["last_change"]:
            ago = max(0, int(now - VLESS_STATE["last_change"]))
            if ago < 60:
                last_activity = f"{ago}s ago"
            elif ago < 3600:
                last_activity = f"{ago // 60}m ago"
            else:
                last_activity = f"{ago // 3600}h ago"
        else:
            last_activity = None

        return {
            "username": "elahe",
            "online": online,
            "uplink": uplink,
            "downlink": downlink,
            "total": total,
            "last_activity": last_activity,
            "online_value": online_value,
        }

    except Exception:
        return None


def _user_key(users, username):
    wanted = (username or "").lower()
    for key in users:
        if key.lower() == wanted:
            return key
    return username


def _new_user(online=False):
    return {
        "pids": [], "ips": [], "since": None, "duration": None,
        "connections": [], "history": [], "online": bool(online),
        "ssh_online": False, "protocols": [], "tunnels": {},
        "usage_total": 0,
    }


def get_all_data():
    active = get_active_users()
    data = {"users": {}, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    for username, info in active.items():
        conns = []
        for pid in info["pids"]:
            conns.extend(get_connections_for_pid(pid))
        conns = sorted(conns, key=lambda x: x["total"], reverse=True)
        user = _new_user(True)
        user.update({
            "pids": info["pids"], "ips": info["ips"],
            "since": info.get("since"), "duration": info.get("duration"),
            "connections": conns, "history": get_history(username),
            "ssh_online": True, "protocols": ["SSH"],
        })
        data["users"][username] = user

    for tunnel in read_tunnel_stats():
        raw_name = tunnel["username"]
        key = _user_key(data["users"], raw_name)
        if key not in data["users"]:
            data["users"][key] = _new_user(tunnel.get("online"))
        user = data["users"][key]
        protocol = tunnel["protocol"]
        online = bool(tunnel.get("online"))
        user["online"] = bool(user.get("online") or online)
        if protocol not in user["protocols"]:
            user["protocols"].append(protocol)
        user["tunnels"][protocol] = {
            "online": online, "duration": tunnel.get("duration"),
            "active_connections": tunnel.get("active_connections", 0),
            "sessions": tunnel.get("sessions", 0), "last_seen": tunnel.get("last_seen"),
            "last_destination": tunnel.get("last_destination"),
            "connected_since": tunnel.get("connected_since_iso")
        }
        user["connections"].append(tunnel["connection"])
        user["usage_total"] += int(tunnel["connection"].get("total", 0) or 0)
        if not user.get("duration") and online:
            user["duration"] = tunnel.get("duration")

    try:
        vless_users = vless_admin.list_users_with_activity()
    except Exception:
        vless_users = []
    for vless in vless_users:
        raw_name = vless["name"]
        key = _user_key(data["users"], raw_name)
        if key not in data["users"]:
            data["users"][key] = _new_user(vless.get("online"))
        user = data["users"][key]
        online = bool(vless.get("online"))
        user["online"] = bool(user.get("online") or online)
        if "VLESS" not in user["protocols"]:
            user["protocols"].append("VLESS")
        if "Cloudflare" not in user["ips"]:
            user["ips"].append("Cloudflare")
        user["tunnels"]["VLESS"] = {
            "online": online, "last_seen": vless.get("last_activity"),
            "uplink": vless["uplink"], "downlink": vless["downlink"],
            "total": vless["total"], "accounting": "persistent-xray-delta",
        }
        user["connections"].append({
            "peer": "Cloudflare", "ip": "Cloudflare", "port": "443",
            "service": "VLESS / Cloudflare", "protocol": "VLESS",
            "sent": vless["uplink"], "recv": vless["downlink"],
            "sent_f": format_bytes(vless["uplink"]), "recv_f": format_bytes(vless["downlink"]),
            "total": vless["total"], "activity": "ACTIVE" if online else "CUMULATIVE",
            "state": "VLESS", "tunnel_connections": 1 if online else 0, "sessions": 0,
        })
        user["usage_total"] += int(vless.get("total", 0) or 0)

    for user in data["users"].values():
        user["connections"] = sorted(user["connections"], key=lambda x: x.get("total", 0), reverse=True)
    data["usage_total"] = sum(int(u.get("usage_total", 0) or 0) for u in data["users"].values())
    data["online_users"] = sum(1 for u in data["users"].values() if u.get("online"))
    return data

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SlipNet Monitor</title>
<style>
:root {
  --bg: #243247;
  --surface: #2c3b52;
  --border: #50617a;
  --accent: #8b5cf6;
  --accent2: #22d3ee;
  --green: #10b981;
  --red: #ef4444;
  --yellow: #f59e0b;
  --text: #f1f5f9;
  --muted: #bbc6d6;
  --card: #33445d;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; min-height: 100vh; padding-bottom: 60px; }

header {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 12px 16px; display: flex; justify-content: space-between; align-items: center;
  position: sticky; top: 0; z-index: 100;
}
.logo { display: flex; align-items: center; gap: 10px; }
.logo-icon { width: 32px; height: 32px; background: linear-gradient(135deg, var(--accent), var(--accent2)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 16px; }
.logo-text { font-size: 15px; font-weight: 700; color: var(--text); letter-spacing: 0.5px; }
.logo-sub { font-size: 10px; color: var(--muted); }
.header-right { display: flex; align-items: center; gap: 12px; }
#clock { font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }
.pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

.stats-bar { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); }
.stat { background: var(--surface); padding: 10px 16px; text-align: center; }
.stat-value { font-size: 20px; font-weight: 700; color: var(--accent2); }
.stat-label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px; }

.users-scroll { display: flex; gap: 10px; padding: 12px 16px; overflow-x: auto; border-bottom: 1px solid var(--border); -webkit-overflow-scrolling: touch; }
.users-scroll::-webkit-scrollbar { height: 3px; }
.users-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.user-chip { flex-shrink: 0; background: var(--card); border: 1.5px solid var(--border); border-radius: 12px; padding: 10px 14px; cursor: pointer; transition: all 0.2s; min-width: 140px; }
.user-chip:active { transform: scale(0.97); }
.user-chip.active { border-color: var(--accent); background: #405572; }
.user-chip-name { font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 6px; }
.user-chip-meta { font-size: 11px; color: var(--muted); margin-top: 4px; }
.user-chip-traffic { font-size: 12px; color: var(--accent2); margin-top: 3px; font-weight: 600; }
.user-chip-duration { font-size: 11px; color: var(--yellow); margin-top: 2px; }

.content { padding: 12px 16px; display: flex; flex-direction: column; gap: 12px; }
.section-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }
.section-count { background: var(--border); padding: 2px 8px; border-radius: 10px; font-size: 10px; color: var(--text); }

.conn-list { display: flex; flex-direction: column; gap: 6px; }
.conn-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px; display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.conn-card.active-conn { border-color: #10b98133; }
.conn-left { flex: 1; min-width: 0; }
.conn-service { font-size: 14px; font-weight: 600; color: var(--text); }
.conn-ip { font-size: 11px; color: var(--muted); margin-top: 2px; font-family: monospace; }
.conn-right { text-align: right; flex-shrink: 0; }
.conn-traffic { font-size: 13px; font-weight: 600; color: var(--accent2); }
.conn-traffic-label { font-size: 10px; color: var(--muted); margin-top: 2px; }

.badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px; }
.badge-active { background: #10b98120; color: var(--green); border: 1px solid #10b98140; }
.badge-normal { background: #06b6d420; color: var(--accent2); border: 1px solid #06b6d440; }
.badge-bg { background: #ffffff10; color: var(--muted); border: 1px solid var(--border); }
.badge-connect { background: #10b98120; color: var(--green); }
.badge-disconnect { background: #ef444420; color: var(--red); }

.history-list { display: flex; flex-direction: column; gap: 1px; background: var(--border); border-radius: 10px; overflow: hidden; }
.hist-row { background: var(--card); padding: 10px 14px; display: flex; align-items: center; gap: 10px; }
.hist-time { font-size: 11px; color: var(--muted); font-family: monospace; flex-shrink: 0; }
.hist-ip { font-size: 12px; color: var(--accent2); font-family: monospace; margin-left: auto; }

.empty { text-align: center; padding: 40px 20px; color: var(--muted); }
.empty-icon { font-size: 32px; margin-bottom: 10px; }

.bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; background: var(--surface); border-top: 1px solid var(--border); padding: 8px 16px 16px; display: flex; justify-content: space-between; align-items: center; }
.bottom-info { font-size: 11px; color: var(--muted); }
.refresh-btn { background: var(--accent); color: white; border: none; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 600; cursor: pointer; }

/* User detail header */
.user-detail-header { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; display: flex; justify-content: space-between; align-items: center; }
.user-detail-info { display: flex; flex-direction: column; gap: 4px; }
.user-detail-name { font-size: 18px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
.user-detail-meta { font-size: 12px; color: var(--muted); }
.user-detail-duration { font-size: 13px; color: var(--yellow); font-weight: 600; }
.disconnect-btn { background: #ef444420; color: var(--red); border: 1px solid #ef444440; border-radius: 8px; padding: 10px 16px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s; white-space: nowrap; }
.disconnect-btn:hover { background: #ef444440; }
.disconnect-btn:active { transform: scale(0.96); }

.service-icon { width: 28px; height: 28px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 14px; margin-right: 10px; flex-shrink: 0; }
.si-telegram { background: #229ED920; color: #229ED9; }
.si-whatsapp { background: #25D36620; color: #25D366; }
.si-instagram { background: #E104A320; color: #E104A3; }
.si-google { background: #4285F420; color: #4285F4; }
.si-other { background: #ffffff10; color: var(--muted); }

/* Toast */
.toast { position: fixed; top: 70px; left: 50%; transform: translateX(-50%); background: #33445d; border: 1px solid var(--border); border-radius: 8px; padding: 10px 20px; font-size: 13px; z-index: 999; opacity: 0; transition: opacity 0.3s; pointer-events: none; }
.toast.show { opacity: 1; }
.toast.success { border-color: var(--green); color: var(--green); }
.toast.error { border-color: var(--red); color: var(--red); }

@media (min-width: 768px) {
  .stats-bar { grid-template-columns: repeat(3, auto); background: none; gap: 0; justify-content: flex-start; }
  .stat { background: none; border-right: 1px solid var(--border); padding: 12px 24px; text-align: left; }
  .stat:first-child { padding-left: 16px; }
  body { padding-bottom: 0; }
  .bottom-nav { display: none; }
  .content { max-width: 900px; margin: 0 auto; padding: 16px; }
}

/* VLESS_ADMIN_UI_V1 */
.vless-admin {
  margin: 14px 16px;
  border: 1px solid var(--border);
  border-radius: 14px;
  overflow: hidden;
  background: var(--card);
}
.vless-admin-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px;
  border-bottom: 1px solid var(--border);
}
.vless-admin-title {
  font-size: 15px;
  font-weight: 700;
}
.vless-add-btn,
.vless-action-btn {
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  border-radius: 8px;
  padding: 7px 10px;
  cursor: pointer;
  font-size: 12px;
}
.vless-add-btn:hover,
.vless-action-btn:hover {
  border-color: var(--accent);
}
.vless-delete-btn {
  opacity: .8;
}
.vless-user-row {
  display: grid;
  grid-template-columns: minmax(100px,1fr) minmax(150px,1.3fr) auto;
  gap: 12px;
  align-items: center;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
}
.vless-user-row:last-child {
  border-bottom: 0;
}
.vless-user-name {
  font-weight: 700;
  font-size: 14px;
}
.vless-user-state {
  font-size: 11px;
  color: var(--muted);
  margin-top: 4px;
}
.vless-dot {
  width: 8px;
  height: 8px;
  display: inline-block;
  border-radius: 50%;
  margin-right: 6px;
  background: #64748b;
}
.vless-dot.online {
  background: #10b981;
  box-shadow: 0 0 6px #10b981;
}
.vless-usage-label { font-size: 9px; color: var(--muted); font-weight: 500; }
.vless-traffic {
  font-size: 12px;
  color: var(--muted);
  line-height: 1.65;
}
.vless-total {
  color: var(--accent2);
  font-weight: 700;
}
.vless-actions {
  display: flex;
  gap: 6px;
}
.vless-admin-msg {
  min-height: 18px;
  padding: 0 14px 10px;
  font-size: 11px;
  color: var(--muted);
}
.vless-loading {
  padding: 18px 14px;
  color: var(--muted);
  font-size: 12px;
}
@media (max-width:700px) {
  .vless-user-row {
    grid-template-columns: 1fr;
    gap: 7px;
  }
  .vless-actions {
    justify-content: flex-start;
  }
}



/* VLESS_UI_CLEANUP_V2 */

.vless-admin {
  margin: 18px 16px;
  border-radius: 18px;
  border: 1px solid rgba(148,163,184,.18);
  overflow: hidden;
  background:
    linear-gradient(
      145deg,
      rgba(255,255,255,.045),
      rgba(255,255,255,.018)
    );
  box-shadow:
    0 14px 36px rgba(0,0,0,.12);
}

.vless-admin-head {
  padding: 16px 18px;
  background: rgba(255,255,255,.025);
}

.vless-admin-title {
  font-size: 16px;
  letter-spacing: -.2px;
}

.vless-admin-sub {
  margin-top: 3px;
  color: var(--muted);
  font-size: 11px;
}

.vless-add-btn {
  padding: 8px 13px;
  border-radius: 10px;
  font-weight: 700;
}

.vless-user-row {
  grid-template-columns:
    minmax(120px,.8fr)
    minmax(120px,.8fr)
    minmax(220px,1.5fr)
    auto;
  gap: 16px;
  padding: 15px 18px;
  transition:
    background .15s ease,
    transform .15s ease;
}

.vless-user-row:hover {
  background: rgba(255,255,255,.025);
}

.vless-user-name {
  font-size: 14px;
}

.vless-user-state {
  display: flex;
  align-items: center;
  gap: 5px;
}

.vless-traffic {
  line-height: 1.7;
}

.vless-total {
  font-size: 13px;
}

.vless-actions {
  align-items: center;
}

.vless-action-btn {
  white-space: nowrap;
  border-radius: 9px;
}

.vless-activity {
  min-width: 0;
}

.vless-activity-title {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--muted);
  margin-bottom: 6px;
}

.app-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.app-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  max-width: 100%;
  padding: 5px 8px;
  border-radius: 999px;
  border: 1px solid rgba(148,163,184,.16);
  background: rgba(148,163,184,.07);
  font-size: 10px;
  color: var(--text);
}

.app-chip.current {
  border-color: rgba(16,185,129,.35);
  background: rgba(16,185,129,.09);
}

.app-chip-dot {
  width: 6px;
  height: 6px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: #64748b;
}

.app-chip.current .app-chip-dot {
  background: #10b981;
  box-shadow: 0 0 5px rgba(16,185,129,.8);
}

.app-chip-name {
  font-weight: 700;
}

.app-chip-age {
  color: var(--muted);
}

.app-host {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 260px;
  color: var(--muted);
  font-size: 9px;
}

.app-empty {
  font-size: 11px;
  color: var(--muted);
}

.stats-bar {
  margin: 0 16px 14px;
  border: 1px solid rgba(148,163,184,.14);
  border-radius: 14px;
  overflow: hidden;
}

.stat {
  padding: 13px 16px;
}

.users-scroll {
  margin: 0 16px 14px;
  border: 1px solid rgba(148,163,184,.12);
  border-radius: 14px;
  padding: 10px;
}

.user-chip {
  border-radius: 12px !important;
  min-width: 145px;
}

.user-detail-header {
  margin: 0 16px 14px;
  border-radius: 14px;
  border: 1px solid rgba(148,163,184,.12);
}

.conn-card {
  border-radius: 12px;
  margin-bottom: 7px;
}

.section-title {
  margin-top: 18px;
  margin-bottom: 8px;
}

@media (max-width: 850px) {
  .vless-user-row {
    grid-template-columns: 1fr 1fr;
  }

  .vless-activity {
    grid-column: 1 / -1;
  }

  .vless-actions {
    justify-content: flex-start;
  }
}

@media (max-width: 560px) {
  .vless-admin {
    margin: 12px 10px;
    border-radius: 15px;
  }

  .vless-admin-head {
    padding: 14px;
  }

  .vless-user-row {
    grid-template-columns: 1fr;
    padding: 14px;
    gap: 10px;
  }

  .vless-activity {
    grid-column: auto;
  }

  .stats-bar,
  .users-scroll,
  .user-detail-header {
    margin-left: 10px;
    margin-right: 10px;
  }

  .app-host {
    max-width: 185px;
  }
}

</style>
</head>
<body>
<div class="toast" id="toast"></div>
<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <div>
      <div class="logo-text">SlipNet Monitor</div>
      <div class="logo-sub">Live Traffic Dashboard</div>
    </div>
  </div>
  <div class="header-right">
    <div class="pulse"></div>
    <span id="clock"></span>
  </div>
</header>


<!-- VLESS_ADMIN_PANEL_V1 -->
<div class="vless-admin">
  <div class="vless-admin-head">
    <div>
      <div class="vless-admin-title">VLESS User Manager</div>
      <div class="vless-admin-sub">Traffic · status · recent activity</div>
    </div>
    <button class="vless-add-btn" onclick="addVlessUser()">+ Add User</button>
  </div>
  <div id="vless-admin-list">
    <div class="vless-loading">Loading VLESS users...</div>
  </div>
  <div class="vless-admin-msg" id="vless-admin-msg"></div>
</div>

<div class="stats-bar">
  <div class="stat"><div class="stat-value" id="stat-users">-</div><div class="stat-label">Online Users</div></div>
  <div class="stat"><div class="stat-value" id="stat-conns">-</div><div class="stat-label">Connections</div></div>
  <div class="stat"><div class="stat-value" id="stat-traffic">-</div><div class="stat-label">Total Traffic</div></div>
</div>

<div class="users-scroll" id="users-scroll">
  <div class="empty" style="padding:20px">Loading...</div>
</div>

<div class="content" id="content">
  <div class="empty"><div class="empty-icon">👆</div>Select a user above</div>
</div>

<div class="bottom-nav">
  <span class="bottom-info" id="last-update">-</span>
  <button class="refresh-btn" onclick="refresh()">⟳ Refresh</button>
</div>

<script>
let selected = null;
let data = {};

function clock() { document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }
setInterval(clock, 1000); clock();

function showToast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 2500);
}

function svcIcon(svc) {
  if (svc.includes('Telegram')) return ['si-telegram','✈'];
  if (svc.includes('WhatsApp')) return ['si-whatsapp','✓'];
  if (svc.includes('Instagram') || svc.includes('Facebook')) return ['si-instagram','◈'];
  if (svc.includes('Google') || svc.includes('YouTube')) return ['si-google','G'];
  return ['si-other','?'];
}

function fmtTotal(bytes) {
  if (bytes >= 1048576) return (bytes/1048576).toFixed(1)+' MB';
  if (bytes >= 1024) return (bytes/1024).toFixed(1)+' KB';
  return bytes+' B';
}

async function refresh() {
  try {
    const r = await fetch('/api/data');
    data = await r.json();
    renderStats();
    renderUsers();
    if (selected && data.users[selected]) renderMain(selected);
    document.getElementById('last-update').textContent = 'Updated: '+data.timestamp;
  } catch(e) {
    document.getElementById('last-update').textContent = 'Connection error';
  }
}

async function disconnectUser(name) {
  if (!confirm(`Disconnect ${name}?`)) return;
  try {
    const r = await fetch('/api/disconnect?user='+encodeURIComponent(name), {method:'POST'});
    const res = await r.json();
    if (res.success) {
      showToast(`${name} disconnected`, 'success');
      setTimeout(refresh, 1000);
    } else {
      showToast('Error: '+res.message, 'error');
    }
  } catch(e) {
    showToast('Request failed', 'error');
  }
}

function renderStats() {
  const users = Number(data.online_users ?? Object.values(data.users).filter(u => u.online).length);
  const conns = Object.values(data.users).reduce((s,u) => s + u.connections.length, 0);
  const traffic = Number(data.usage_total ?? Object.values(data.users).reduce((s,u) => s + Number(u.usage_total || 0), 0));
  document.getElementById('stat-users').textContent = users;
  document.getElementById('stat-conns').textContent = conns;
  document.getElementById('stat-traffic').textContent = fmtTotal(traffic);
}

function renderUsers() {
  const el = document.getElementById('users-scroll');
  const users = data.users || {};
  if (!Object.keys(users).length) {
    el.innerHTML = '<div class="empty" style="padding:20px;white-space:nowrap">No users online</div>';
    return;
  }
  let html = '';
  for (const [name, info] of Object.entries(users)) {
    const active = selected === name ? 'active' : '';
    const total = info.connections.reduce((s,c) => s+c.total, 0);
    const activeConns = info.connections.filter(c => c.activity === 'ACTIVE').length;
    html += `<div class="user-chip ${active}" onclick="selectUser('${name}')">
      <div class="user-chip-name"><span style="width:8px;height:8px;border-radius:50%;background:#10b981;display:inline-block;box-shadow:0 0 6px #10b981"></span>${name}</div>
      <div class="user-chip-meta">${info.ips[0] || ''}</div>
      <div class="user-chip-traffic">${fmtTotal(total)}${activeConns ? ' · '+activeConns+' active' : ''}</div>
      ${info.duration ? `<div class="user-chip-duration">⏱ ${info.duration}</div>` : ''}
    </div>`;
  }
  el.innerHTML = html;
}

function selectUser(name) {
  selected = name;
  document.querySelectorAll('.user-chip').forEach(el => {
    el.classList.toggle('active', el.querySelector('.user-chip-name').textContent.trim().includes(name));
  });
  renderMain(name);
}

function renderMain(name) {
  const info = data.users[name];
  if (!info) return;
  const el = document.getElementById('content');

  // User detail header with disconnect button
  const detailHeader = `
    <div class="user-detail-header">
      <div class="user-detail-info">
        <div class="user-detail-name">
          <span style="width:10px;height:10px;border-radius:50%;background:#10b981;display:inline-block;box-shadow:0 0 8px #10b981"></span>
          ${name}
        </div>
        <div class="user-detail-meta">IP: ${info.ips.join(', ')}</div>
        ${info.since ? `<div class="user-detail-meta">Connected since: ${info.since}</div>` : ''}
        ${info.duration ? `<div class="user-detail-duration">⏱ Online for ${info.duration}</div>` : ''}
      </div>
      <button class="disconnect-btn" onclick="disconnectUser('${name}')">⏏ Disconnect</button>
    </div>`;

  // Connections
  let connHtml = '';
  const active = info.connections.filter(c => c.activity !== 'Background');
  const bg = info.connections.filter(c => c.activity === 'Background');

  if (active.length) {
    connHtml += `<div><div class="section-title">Active Connections <span class="section-count">${active.length}</span></div><div class="conn-list">`;
    for (const c of active) {
      const [iconClass, iconChar] = svcIcon(c.service);
      const badgeClass = c.activity === 'ACTIVE' ? 'badge-active' : 'badge-normal';
      connHtml += `<div class="conn-card ${c.activity==='ACTIVE'?'active-conn':''}">
        <div class="service-icon ${iconClass}">${iconChar}</div>
        <div class="conn-left">
          <div class="conn-service">${c.service} <span class="badge ${badgeClass}">${c.activity}</span></div>
          <div class="conn-ip">${c.peer}</div>
        </div>
        <div class="conn-right">
          <div class="conn-traffic">${fmtTotal(c.total)}</div>
          <div class="conn-traffic-label">↑${c.sent_f} ↓${c.recv_f}</div>
        </div>
      </div>`;
    }
    connHtml += '</div></div>';
  }

  if (bg.length) {
    connHtml += `<div><div class="section-title">Background <span class="section-count">${bg.length}</span></div><div class="conn-list">`;
    for (const c of bg) {
      const [iconClass, iconChar] = svcIcon(c.service);
      connHtml += `<div class="conn-card">
        <div class="service-icon ${iconClass}" style="opacity:0.5">${iconChar}</div>
        <div class="conn-left">
          <div class="conn-service" style="color:var(--muted)">${c.service} <span class="badge badge-bg">BG</span></div>
          <div class="conn-ip">${c.peer}</div>
        </div>
        <div class="conn-right">
          <div class="conn-traffic" style="color:var(--muted);font-size:11px">${fmtTotal(c.total)}</div>
        </div>
      </div>`;
    }
    connHtml += '</div></div>';
  }

  if (!connHtml) connHtml = '<div class="empty"><div class="empty-icon">📡</div>No connections</div>';

  // History
  const hist = [...(info.history||[])].reverse().slice(0,15);
  let histHtml = '<div class="history-list">';
  for (const h of hist) {
    const badge = h.type === 'connect' ? 'badge-connect' : 'badge-disconnect';
    const label = h.type === 'connect' ? '▲ ON' : '▼ OFF';
    histHtml += `<div class="hist-row">
      <span class="badge ${badge}">${label}</span>
      <span class="hist-time">${h.time}</span>
      ${h.ip ? `<span class="hist-ip">${h.ip}</span>` : ''}
    </div>`;
  }
  histHtml += '</div>';

  el.innerHTML = `
    ${detailHeader}
    ${connHtml}
    <div>
      <div class="section-title">Connection History <span class="section-count">${hist.length}</span></div>
      ${histHtml}
    </div>`;
}

refresh();
setInterval(refresh, 5000);
</script>

<script>
/* VLESS_ADMIN_JS_V1 */

function vlessMsg(text) {
  const el = document.getElementById('vless-admin-msg');
  if (el) el.textContent = text || '';
}

function vlessEsc(text) {
  return String(text ?? '')
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}

async function loadVlessUsers() {
  try {
    const r = await fetch('/api/vless/users', {cache:'no-store'});

    if (!r.ok) throw new Error('HTTP ' + r.status);

    const payload = await r.json();
    const users = payload.users || [];
    const el = document.getElementById('vless-admin-list');

    if (!el) return;

    if (!users.length) {
      el.innerHTML = '<div class="vless-loading">No VLESS users</div>';
      return;
    }

    el.innerHTML = users.map(u => `
      <div class="vless-user-row">
        <div>
          <div class="vless-user-name">
            <span class="vless-dot ${u.online ? 'online' : ''}"></span>
            ${vlessEsc(u.name)}
          </div>
          <div class="vless-user-state">
            ${u.access_state === 'active' ? (u.online ? 'Online' : 'Offline') : ('Blocked · ' + vlessEsc(u.access_state))}
            ${u.last_activity ? ' · ' + vlessEsc(u.last_activity) : ''}
          </div>
        </div>

        <div class="vless-traffic">
          <span class="vless-total">${vlessEsc(u.total_f)}</span><br><span class="vless-usage-label">Usage since subscription baseline</span><br>
          ↑ ${vlessEsc(u.uplink_f)} &nbsp; ↓ ${vlessEsc(u.downlink_f)}<br>
          <span class="vless-usage-label">Quota: ${vlessEsc(u.quota_f || 'Unlimited')} · Remaining: ${vlessEsc(u.remaining_f || 'Unlimited')} · Days: ${u.days_left == null ? 'Unlimited' : vlessEsc(u.days_left)}</span>
        </div>

        <div class="vless-actions">
          <button class="vless-action-btn"
                  onclick="copyVlessConfig('${vlessEsc(u.name)}')">Copy Encrypted</button>
          <button class="vless-action-btn"
                  onclick="showVlessQr('${vlessEsc(u.name)}')">QR</button>
          <button class="vless-action-btn"
                  onclick="downloadVlessConfig('${vlessEsc(u.name)}')">Download EA</button>
          <button class="vless-action-btn"
                  onclick="editVlessLimits('${vlessEsc(u.name)}')">Limits</button>
          <button class="vless-action-btn"
                  onclick="resetVlessUsage('${vlessEsc(u.name)}')">Reset Usage</button>
          <button class="vless-action-btn"
                  onclick="rotateVlessPassword('${vlessEsc(u.name)}')">Password</button>
          <button class="vless-action-btn vless-delete-btn"
                  onclick="deleteVlessUser('${vlessEsc(u.name)}')">
            Delete
          </button>
        </div>
      </div>
    `).join('');

  } catch (e) {
    vlessMsg('VLESS API error: ' + e.message);
  }
}

async function addVlessUser() {
  const name = prompt('New VLESS user name:');
  if (!name) return;
  const daysRaw = prompt('Subscription duration in days (0 = unlimited):', '30');
  if (daysRaw === null) return;
  const days = Number.parseInt(daysRaw, 10);
  if (!Number.isFinite(days) || days < 0) { vlessMsg('Invalid subscription days'); return; }
  const quotaRaw = prompt('Traffic quota in GB (0 = unlimited):', '0');
  if (quotaRaw === null) return;
  const quotaGb = Number.parseFloat(quotaRaw);
  if (!Number.isFinite(quotaGb) || quotaGb < 0) { vlessMsg('Invalid traffic quota'); return; }
  const password = prompt('Delivery/import password (minimum 6 characters):');
  if (!password || password.length < 6) { vlessMsg('Password must be at least 6 characters'); return; }

  vlessMsg('Creating ' + name + '...');
  try {
    const r = await fetch('/api/vless/add', {
      method: 'POST',
      headers: {'Content-Type':'application/json','X-Requested-With':'SlipNetMonitor'},
      body: JSON.stringify({
        name,
        duration_days: days,
        quota_bytes: Math.round(quotaGb * 1024 * 1024 * 1024),
        password
      })
    });
    const result = await r.json();
    if (!r.ok || !result.success) throw new Error(result.error || 'Create failed');
    vlessMsg('User created: encrypted EA v29 Primary + Backup ready');
    await loadVlessUsers();
    await downloadVlessConfig(result.name);
  } catch (e) {
    vlessMsg('Create failed: ' + e.message);
  }
}

async function editVlessLimits(name) {
  const daysRaw = prompt('New subscription duration from now, days (0 = unlimited):', '30');
  if (daysRaw === null) return;
  const quotaRaw = prompt('New traffic quota in GB (0 = unlimited):', '0');
  if (quotaRaw === null) return;
  const days = Number.parseInt(daysRaw, 10);
  const quotaGb = Number.parseFloat(quotaRaw);
  if (!Number.isFinite(days) || days < 0 || !Number.isFinite(quotaGb) || quotaGb < 0) {
    vlessMsg('Invalid limits'); return;
  }
  const r = await fetch('/api/vless/limits', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Requested-With':'SlipNetMonitor'},
    body:JSON.stringify({name,duration_days:days,quota_bytes:Math.round(quotaGb*1024*1024*1024)})
  });
  const result = await r.json();
  if (!r.ok || !result.success) { vlessMsg('Limit update failed: '+(result.error||'unknown error')); return; }
  vlessMsg('Limits updated for '+name+'. Rotate password to issue an artifact with the new client-visible expiry.');
  await loadVlessUsers();
}

async function resetVlessUsage(name) {
  if (!confirm('Reset server usage baseline for ' + name + '?')) return;
  const r = await fetch('/api/vless/reset-usage', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Requested-With':'SlipNetMonitor'},
    body:JSON.stringify({name})
  });
  const result = await r.json();
  if (!r.ok || !result.success) { vlessMsg('Usage reset failed: '+(result.error||'unknown error')); return; }
  vlessMsg('Usage baseline reset for ' + name);
  await loadVlessUsers();
}

async function rotateVlessPassword(name) {
  const password = prompt('New delivery/import password (minimum 6 characters):');
  if (!password || password.length < 6) return;
  const r = await fetch('/api/vless/password', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-Requested-With':'SlipNetMonitor'},
    body:JSON.stringify({name,password})
  });
  const result = await r.json();
  if (!r.ok || !result.success) { vlessMsg('Password rotation failed: '+(result.error||'unknown error')); return; }
  vlessMsg('Encrypted artifact regenerated for ' + name);
}

function showVlessQr(name) {
  window.open('/api/vless/qr?user=' + encodeURIComponent(name), '_blank', 'noopener,noreferrer');
}

async function deleteVlessUser(name) {
  if (!confirm('Delete VLESS user "' + name + '"?'))
    return;

  vlessMsg('Deleting ' + name + '...');

  try {
    const r = await fetch('/api/vless/delete', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'SlipNetMonitor'
      },
      body: JSON.stringify({name})
    });

    const result = await r.json();

    if (!r.ok || !result.success)
      throw new Error(result.error || 'Delete failed');

    vlessMsg('Deleted: ' + name);
    await loadVlessUsers();

  } catch (e) {
    vlessMsg('Delete failed: ' + e.message);
  }
}

async function copyVlessConfig(name) {
  try {
    const r = await fetch(
      '/api/vless/config?user=' + encodeURIComponent(name),
      {cache:'no-store'}
    );

    const result = await r.json();

    if (!r.ok || !result.success)
      throw new Error(result.error || 'Config failed');

    try {
      await navigator.clipboard.writeText(result.bundle || result.uri);
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = result.bundle || result.uri;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }

    vlessMsg('EA v29 Primary + Backup copied for ' + name);

  } catch (e) {
    vlessMsg('Copy failed: ' + e.message);
  }
}

async function downloadVlessConfig(name) {
  const a = document.createElement('a');
  a.href = '/api/vless/download?user=' + encodeURIComponent(name);
  a.download = name + '.slipnet';
  document.body.appendChild(a);
  a.click();
  a.remove();
  vlessMsg('Downloading EA v29 Primary + Backup for ' + name);
}

window.__vlessLegacyTimeout = setTimeout(loadVlessUsers, 200);
window.__vlessLegacyTimer = setInterval(loadVlessUsers, 3000);
</script>


<script>
/* VLESS_ACTIVITY_UI_V2 */

function activityChip(a) {
  const current = a.current ? ' current' : '';

  const confidence =
    a.confidence === 'high'
      ? ''
      : ` · ${vlessEsc(a.confidence || '')}`;

  return `
    <div class="app-chip${current}"
         title="${vlessEsc(a.host)}:${vlessEsc(a.port)} · ${vlessEsc(a.protocol)}${confidence}">
      <span class="app-chip-dot"></span>
      <span class="app-chip-name">${vlessEsc(a.service)}</span>
      <span class="app-chip-age">${vlessEsc(a.age)}</span>
    </div>
  `;
}

async function loadVlessUsers() {
  try {
    const r = await fetch(
      '/api/vless/users',
      {cache:'no-store'}
    );

    if (!r.ok)
      throw new Error('HTTP ' + r.status);

    const payload = await r.json();
    const users = payload.users || [];

    const el =
      document.getElementById('vless-admin-list');

    if (!el)
      return;

    if (!users.length) {
      el.innerHTML =
        '<div class="vless-loading">No VLESS users</div>';
      return;
    }

    el.innerHTML = users.map(u => {

      const activity =
        (u.activity || []).slice(0, 4);

      let activityHtml = '';

      if (activity.length) {
        activityHtml = `
          <div class="app-list">
            ${activity.map(activityChip).join('')}
          </div>

          <div class="app-host"
               title="${vlessEsc(activity[0].host)}">
            ${vlessEsc(activity[0].host)}
          </div>
        `;
      } else {
        activityHtml =
          '<div class="app-empty">No recent activity</div>';
      }

      return `
        <div class="vless-user-row">

          <div>
            <div class="vless-user-name">
              <span class="vless-dot ${u.online ? 'online' : ''}"></span>
              ${vlessEsc(u.name)}
            </div>

            <div class="vless-user-state">
              ${u.online ? 'Online' : 'Offline'}
              ${u.last_activity
                ? ' · ' + vlessEsc(u.last_activity)
                : ''}
            </div>
          </div>

          <div class="vless-traffic">
            <span class="vless-total">
              ${vlessEsc(u.total_f)}
            </span>
            <br><span class="vless-usage-label">Cumulative server usage</span>
            <br>
            ↑ ${vlessEsc(u.uplink_f)}
            &nbsp;
            ↓ ${vlessEsc(u.downlink_f)}
          </div>

          <div class="vless-activity">
            <div class="vless-activity-title">
              Current / Recent Activity
            </div>
            ${activityHtml}
          </div>

          <div class="vless-actions">
            <button
              class="vless-action-btn"
              onclick="copyVlessConfig('${vlessEsc(u.name)}')">
              Copy
            </button>

            <button class="vless-action-btn"
              onclick="downloadVlessConfig('${vlessEsc(u.name)}')">Download EA</button>
            <button
              class="vless-action-btn vless-delete-btn"
              onclick="deleteVlessUser('${vlessEsc(u.name)}')">
              Delete
            </button>
          </div>

        </div>
      `;
    }).join('');

  } catch (e) {
    vlessMsg(
      'VLESS API error: ' + e.message
    );
  }
}


/* VLESS_ACTIVITY_REFRESH_OWNER_V3 */

if (window.__vlessLegacyTimeout) {
  clearTimeout(window.__vlessLegacyTimeout);
  window.__vlessLegacyTimeout = null;
}

if (window.__vlessLegacyTimer) {
  clearInterval(window.__vlessLegacyTimer);
  window.__vlessLegacyTimer = null;
}

if (window.__vlessActivityTimer) {
  clearInterval(window.__vlessActivityTimer);
}

loadVlessUsers();

window.__vlessActivityTimer =
  setInterval(loadVlessUsers, 3000);

</script>

</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def check_auth(self):
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(f'admin:{PASSWORD}'.encode()).decode()
        if auth != expected:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="SlipNet Monitor"')
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Unauthorized')
            return False
        return True

    def send_json(self, payload, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.path)

        # Device-side managed subscription usage. This endpoint remains bound
        # to localhost and is reached through an already-authenticated VLESS
        # tunnel. The VLESS UUID is reused as the subscription identity; no
        # monitor/admin credential is ever shipped to the app.
        if parsed.path == '/api/subscription/usage':
            try:
                token = self.headers.get('X-SlipNet-Subscription', '')
                payload = vless_admin.subscription_usage_for_token(token)
                body = json.dumps(payload, separators=(',', ':')).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
            except PermissionError:
                body = b'{"success":false,"error":"Forbidden"}'
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                body = b'{"success":false,"error":"Unavailable"}'
                self.send_response(503)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
            return

        if not self.check_auth():
            return

        if parsed.path == '/api/vless/users':
            try:
                self.send_json({
                    "success": True,
                    "users": vless_admin.list_users_with_activity()
                })
            except Exception as e:
                self.send_json({
                    "success": False,
                    "error": str(e)[:500]
                }, 500)
            return

        if parsed.path == '/api/vless/config':
            try:
                qs = parse_qs(parsed.query)
                username = qs.get("user", [""])[0]

                payload = vless_admin.config_payload(username)
                self.send_json(payload)
            except Exception as e:
                self.send_json({
                    "success": False,
                    "error": str(e)[:500]
                }, 400)
            return

        if parsed.path == '/api/vless/qr':
            try:
                qs = parse_qs(parsed.query)
                username = qs.get("user", [""])[0]
                payload = vless_admin.config_payload(username)
                proc = subprocess.run(
                    ["qrencode", "-t", "PNG", "-o", "-"],
                    input=payload["bundle"].encode(),
                    capture_output=True,
                    timeout=10,
                )
                if proc.returncode != 0 or not proc.stdout:
                    raise RuntimeError("QR encoder unavailable")
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(proc.stdout)))
                self.end_headers()
                self.wfile.write(proc.stdout)
            except Exception as e:
                self.send_json({"success": False, "error": str(e)[:500]}, 400)
            return

        if parsed.path == '/api/vless/download':
            try:
                qs = parse_qs(parsed.query)
                username = qs.get("user", [""])[0]
                path, payload = vless_admin.profile_artifact(username)
                content = path.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="' + payload["filename"] + '"')
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_json({"success": False, "error": str(e)[:500]}, 400)
            return

        if parsed.path == '/api/data':
            self.send_json(get_all_data())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(HTML.encode())

    def do_POST(self):
        if not self.check_auth():
            return

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.path)

        if parsed.path in (
            '/api/vless/add',
            '/api/vless/delete',
            '/api/vless/limits',
            '/api/vless/reset-usage',
            '/api/vless/password',
        ):

            if self.headers.get('X-Requested-With') != 'SlipNetMonitor':
                self.send_json({
                    "success": False,
                    "error": "Rejected request"
                }, 403)
                return

            try:
                length = int(self.headers.get('Content-Length', '0') or 0)

                if length < 1 or length > 4096:
                    raise ValueError("Invalid request size")

                body = self.rfile.read(length)
                payload = json.loads(body.decode())

                username = payload.get("name", "")

                if parsed.path == '/api/vless/add':
                    result = vless_admin.add_user(
                        username,
                        duration_days=payload.get("duration_days", 30),
                        quota_bytes=payload.get("quota_bytes", 0),
                        delivery_password=payload.get("password", ""),
                    )
                elif parsed.path == '/api/vless/delete':
                    result = vless_admin.delete_user(username)
                elif parsed.path == '/api/vless/limits':
                    result = vless_admin.update_user_limits(
                        username,
                        duration_days=payload.get("duration_days"),
                        quota_bytes=payload.get("quota_bytes"),
                    )
                elif parsed.path == '/api/vless/reset-usage':
                    result = vless_admin.reset_user_usage(username)
                else:
                    result = vless_admin.rotate_delivery_password(
                        username,
                        payload.get("password", ""),
                    )

                self.send_json(result)

            except ValueError as e:
                self.send_json({
                    "success": False,
                    "error": str(e)
                }, 400)

            except Exception as e:
                self.send_json({
                    "success": False,
                    "error": str(e)[:500]
                }, 500)

            return

        if parsed.path == '/api/disconnect':
            qs = parse_qs(parsed.query)
            username = qs.get("user", [""])[0]

            if username:
                result = disconnect_user(username)
            else:
                result = {
                    "success": False,
                    "message": "No user specified"
                }

            self.send_json(result)
            return

        self.send_json({
            "success": False,
            "error": "Unknown endpoint"
        }, 404)

def subscription_enforcement_loop():
    while True:
        try:
            # list_users() is the server authority that reconciles persistent
            # usage and revokes/re-enables runtime VLESS access for quota/expiry.
            vless_admin.list_users()
        except Exception:
            pass
        time.sleep(5)


if __name__ == '__main__':
    port = 8080
    print(f"SlipNet Monitor running on port {port}")
    print("SlipNet Monitor authentication enabled")
    threading.Thread(
        target=subscription_enforcement_loop,
        name="subscription-enforcer",
        daemon=True,
    ).start()
    HTTPServer(('127.0.0.1', port), Handler).serve_forever()

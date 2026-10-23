import ipaddress
import gzip
import bisect
import base64
import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid as uuidlib
from datetime import datetime

XRAY = os.environ.get("SLIPNET_XRAY_BIN", "/usr/local/bin/xray")
CFG = os.environ.get("SLIPNET_XRAY_CONFIG", "/usr/local/etc/xray/config.json")
API = os.environ.get("SLIPNET_XRAY_API", "127.0.0.1:10085")
TAG = os.environ.get("SLIPNET_VLESS_INBOUND_TAG", "vless-cf-tunnel")
PUBLIC_HOST = os.environ.get("SLIPNET_VLESS_PUBLIC_HOST", "").strip()
CDN_IP_FILE = os.environ.get("SLIPNET_CDN_IP_FILE", "/etc/slipnet-ea/vless-cdn-ip.txt")

LOCK = threading.Lock()
STATE = {}


def _run(args, timeout=10):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _load():
    with open(CFG) as f:
        return json.load(f)


def _inbound(cfg):
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == TAG:
            return ib
    raise RuntimeError(f"{TAG} inbound not found")


def _clients(cfg):
    return _inbound(cfg).setdefault("settings", {}).setdefault("clients", [])


def _validate_name(name):
    name = (name or "").strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name):
        raise ValueError(
            "Name must be 1-32 characters: letters, numbers, _, . or -"
        )

    return name


def _write_temp_json(obj, directory="/tmp"):
    fd, path = tempfile.mkstemp(
        prefix="xray-vless-admin-",
        suffix=".json",
        dir=directory,
    )

    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")

    return path


def _validate_config(cfg):
    path = _write_temp_json(cfg)

    try:
        p = _run(
            [XRAY, "run", "-test", "-config", path],
            timeout=15,
        )

        if p.returncode != 0:
            msg = (p.stderr or p.stdout or "Xray config validation failed").strip()
            raise RuntimeError(msg[-1200:])
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _persist(cfg):
    st = os.stat(CFG)

    backup = (
        CFG
        + ".ui-backup-"
        + datetime.now().strftime("%Y%m%d-%H%M%S")
    )
    shutil.copy2(CFG, backup)

    directory = os.path.dirname(CFG)
    fd, tmp = tempfile.mkstemp(
        prefix=".config.json.vless-admin-",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, st.st_mode & 0o7777)
        os.chown(tmp, st.st_uid, st.st_gid)

        os.replace(tmp, CFG)

    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _runtime_add(client, source_cfg):
    ib = copy.deepcopy(_inbound(source_cfg))
    ib["settings"]["clients"] = [copy.deepcopy(client)]

    path = _write_temp_json({"inbounds": [ib]})

    try:
        p = _run(
            [
                XRAY,
                "api",
                "adu",
                "--server=" + API,
                path,
            ]
        )

        output = (p.stdout or "") + "\n" + (p.stderr or "")

        if p.returncode != 0 or "Added 1 user(s)" not in output:
            raise RuntimeError(output.strip() or "Runtime add failed")

    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _runtime_remove(email):
    p = _run(
        [
            XRAY,
            "api",
            "rmu",
            "--server=" + API,
            "-tag=" + TAG,
            email,
        ]
    )

    output = (p.stdout or "") + "\n" + (p.stderr or "")

    if p.returncode != 0 or "Removed 1 user(s)" not in output:
        raise RuntimeError(output.strip() or "Runtime remove failed")


def _stats():
    p = _run(
        [
            XRAY,
            "api",
            "statsquery",
            "--server=" + API,
        ],
        timeout=5,
    )

    if p.returncode != 0:
        return None

    try:
        raw = json.loads(p.stdout)
    except Exception:
        return None

    result = {}

    for item in raw.get("stat", []):
        try:
            result[item.get("name", "")] = int(item.get("value", 0) or 0)
        except Exception:
            result[item.get("name", "")] = 0

    return result


def _fmt_bytes(value):
    value = int(value or 0)

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{value} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024

    return "0 B"


def list_users():
    cfg = _load()
    stats = _stats()
    now = time.time()
    out = []

    valid_names = set()

    for client in _clients(cfg):
        email = client.get("email")

        if not email:
            continue

        valid_names.add(email)

        up = stats.get(
            f"user>>>{email}>>>traffic>>>uplink",
            0,
        )
        down = stats.get(
            f"user>>>{email}>>>traffic>>>downlink",
            0,
        )
        total = up + down

        state = STATE.setdefault(
            email,
            {
                "total": total,
                "last_change": 0,
            },
        )

        if total != state["total"]:
            state["total"] = total
            state["last_change"] = now

        online = bool(
            state["last_change"]
            and now - state["last_change"] <= 30
        )

        if state["last_change"]:
            ago = max(0, int(now - state["last_change"]))
            if ago < 60:
                last_activity = f"{ago}s ago"
            elif ago < 3600:
                last_activity = f"{ago // 60}m ago"
            else:
                last_activity = f"{ago // 3600}h ago"
        else:
            last_activity = None

        out.append(
            {
                "name": email,
                "online": online,
                "uplink": up,
                "downlink": down,
                "total": total,
                "uplink_f": _fmt_bytes(up),
                "downlink_f": _fmt_bytes(down),
                "total_f": _fmt_bytes(total),
                "last_activity": last_activity,
            }
        )

    # Drop state of deleted users.
    for old in list(STATE):
        if old not in valid_names:
            STATE.pop(old, None)

    out.sort(
        key=lambda x: (
            not x["online"],
            x["name"].lower(),
        )
    )

    return out


def add_user(name):
    name = _validate_name(name)

    with LOCK:
        cfg = _load()
        clients = _clients(cfg)

        if any(
            (c.get("email") or "").lower() == name.lower()
            for c in clients
        ):
            raise ValueError("User already exists")

        client = {
            "id": str(uuidlib.uuid4()),
            "email": name,
        }

        new_cfg = copy.deepcopy(cfg)
        _clients(new_cfg).append(copy.deepcopy(client))

        _validate_config(new_cfg)

        # Runtime first. If persistence fails, undo runtime.
        _runtime_add(client, cfg)

        try:
            _persist(new_cfg)
        except Exception:
            try:
                _runtime_remove(name)
            except Exception:
                pass
            raise

        return {
            "success": True,
            "name": name,
        }


def delete_user(name):
    name = _validate_name(name)

    with LOCK:
        cfg = _load()
        clients = _clients(cfg)

        old_client = None

        for c in clients:
            if (c.get("email") or "").lower() == name.lower():
                old_client = copy.deepcopy(c)
                name = c.get("email")
                break

        if old_client is None:
            raise ValueError("User not found")

        new_cfg = copy.deepcopy(cfg)
        new_clients = _clients(new_cfg)

        new_clients[:] = [
            c for c in new_clients
            if (c.get("email") or "").lower() != name.lower()
        ]

        _validate_config(new_cfg)

        _runtime_remove(name)

        try:
            _persist(new_cfg)

        except Exception:
            # Best-effort rollback in runtime.
            try:
                _runtime_add(old_client, cfg)
            except Exception:
                pass
            raise

        STATE.pop(name, None)

        return {
            "success": True,
            "name": name,
        }


def _get_client(name):
    name = _validate_name(name)
    cfg = _load()

    for client in _clients(cfg):
        if (client.get("email") or "").lower() == name.lower():
            return cfg, client

    raise ValueError("User not found")


def config_uri(name):
    cfg, client = _get_client(name)

    ib = _inbound(cfg)

    path = (
        ib.get("streamSettings", {})
        .get("wsSettings", {})
        .get("path")
    )

    if not path:
        raise RuntimeError("VLESS WebSocket path not found")

    with open(CDN_IP_FILE) as f:
        cdn_ip = f.read().strip()

    if not cdn_ip:
        raise RuntimeError("CDN IP is empty")

    email = client["email"]
    uid = client["id"]

    # Exact working SlipNet profile layout.
    fields = [
        "28",
        "vless",
        f"CF-{email}",
        PUBLIC_HOST,
        "",
        "0",
        "5000",
        "bbr",
        "1080",
        "127.0.0.1",
        "0",
        "",
        "",
        "",
        "0",
        "",
        "",
        "22",
        "0",
        "127.0.0.1",
        "0",
        "",
        "udp",
        "password",
        "",
        "",
        "",
        "0",
        "443",
        "",
        "",
        "0",
        "",
        "0",
        "0",
        "",
        "0",
        "",
        "0",
        "0",
        "1080",
        "0",
        "txt",
        "101",
        "0.0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "",
        "",
        "8080",
        "",
        "0",
        "/",
        "1",
        "",
        "",
        "roundrobin",
        "3",
        uid,
        "tls",
        "ws",
        path,
        cdn_ip,
        "443",
        "0",
        "micro",
        "100",
        "",
        "1",
        "1",
        "0",
        "8",
        "",
        "0",
        PUBLIC_HOST,
    ]

    if len(fields) != 79:
        raise RuntimeError("Unexpected SlipNet profile layout")

    payload = "|".join(fields).encode()
    encoded = base64.b64encode(payload).decode()

    return "slipnet://" + encoded


# VLESS_ACTIVITY_DETECTION_V1

_ACTIVITY_CACHE = {
    "at": 0,
    "data": {}
}


def _domain_match(host, domains):
    host = (host or "").lower().rstrip(".")

    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return True

    return False



# VLESS_IP_ASN_DETECTION_V2

IPDB4 = "/var/lib/vless-ipdb/ip2asn-v4-u32.tsv.gz"
IPDB6 = "/var/lib/vless-ipdb/ip2asn-v6.tsv.gz"

_IPDB_LOCK = threading.Lock()

_IP4_READY = False
_IP4_STARTS = []
_IP4_ROWS = []

_IP6_READY = False
_IP6_STARTS = []
_IP6_ROWS = []


def _load_ipv4_db():
    global _IP4_READY, _IP4_STARTS, _IP4_ROWS

    if _IP4_READY:
        return

    with _IPDB_LOCK:
        if _IP4_READY:
            return

        starts = []
        rows = []

        try:
            with gzip.open(
                IPDB4,
                "rt",
                encoding="utf-8",
                errors="replace",
            ) as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t", 4)

                    if len(parts) != 5:
                        continue

                    start, end, asn, country, org = parts

                    try:
                        start = int(start)
                        end = int(end)
                        asn = int(asn)
                    except Exception:
                        continue

                    starts.append(start)
                    rows.append(
                        (start, end, asn, country, org)
                    )

        except Exception:
            starts = []
            rows = []

        _IP4_STARTS = starts
        _IP4_ROWS = rows
        _IP4_READY = True


def _load_ipv6_db():
    global _IP6_READY, _IP6_STARTS, _IP6_ROWS

    if _IP6_READY:
        return

    with _IPDB_LOCK:
        if _IP6_READY:
            return

        starts = []
        rows = []

        try:
            with gzip.open(
                IPDB6,
                "rt",
                encoding="utf-8",
                errors="replace",
            ) as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t", 4)

                    if len(parts) != 5:
                        continue

                    start, end, asn, country, org = parts

                    try:
                        start_i = int(ipaddress.ip_address(start))
                        end_i = int(ipaddress.ip_address(end))
                        asn = int(asn)
                    except Exception:
                        continue

                    starts.append(start_i)
                    rows.append(
                        (start_i, end_i, asn, country, org)
                    )

        except Exception:
            starts = []
            rows = []

        _IP6_STARTS = starts
        _IP6_ROWS = rows
        _IP6_READY = True


def _lookup_ip_asn(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text)
    except Exception:
        return None

    key = int(ip)

    if ip.version == 4:
        _load_ipv4_db()
        starts = _IP4_STARTS
        rows = _IP4_ROWS
    else:
        _load_ipv6_db()
        starts = _IP6_STARTS
        rows = _IP6_ROWS

    if not starts:
        return None

    pos = bisect.bisect_right(starts, key) - 1

    if pos < 0:
        return None

    start, end, asn, country, org = rows[pos]

    if key > end:
        return None

    if asn == 0:
        return None

    return {
        "asn": asn,
        "country": country,
        "org": org,
    }


_ASN_SERVICE_RULES = [
    # Very strong app/service ownership
    ("TELEGRAM", "Telegram", "high"),
    ("NETFLIX", "Netflix", "high"),
    ("SPOTIFY", "Spotify", "high"),
    ("DISCORD", "Discord", "high"),
    ("REDDIT", "Reddit", "high"),
    ("GITHUB", "GitHub Network", "high"),

    # Large service/network owners.
    # These may host multiple products, so do not pretend
    # we know the exact app from the IP alone.
    ("FACEBOOK", "Meta Network", "medium"),
    ("META PLATFORMS", "Meta Network", "medium"),

    ("GOOGLE", "Google Network", "medium"),

    ("MICROSOFT", "Microsoft / Azure", "medium"),
    ("MSFT", "Microsoft / Azure", "medium"),

    ("AMAZON", "Amazon / AWS", "medium"),

    ("APPLE", "Apple Network", "medium"),

    ("CLOUDFLARE", "Cloudflare Network", "medium"),

    ("AKAMAI", "Akamai CDN", "medium"),

    ("FASTLY", "Fastly CDN", "medium"),

    ("BYTEPLUS", "ByteDance / TikTok Network", "medium"),
    ("BYTEDANCE", "ByteDance / TikTok Network", "medium"),

    ("TWITTER", "X / Twitter Network", "medium"),
]



# VLESS_ACTIVITY_POLISH_V3

_NETWORK_DISPLAY_NAMES = [
    ("AFRANET", "Afranet"),
    ("SERVERS-COM", "Servers.com"),
    ("SERVERS.COM", "Servers.com"),
    ("HETZNER", "Hetzner"),
    ("OVH", "OVH"),
    ("DIGITALOCEAN", "DigitalOcean"),
    ("VULTR", "Vultr"),
    ("CHOOPA", "Vultr"),
    ("M247", "M247"),
    ("CONTABO", "Contabo"),
    ("ORACLE", "Oracle Cloud"),
    ("ALIBABA", "Alibaba Cloud"),
    ("LINODE", "Linode"),
    ("AKAMAI", "Akamai"),
    ("LEASEWEB", "Leaseweb"),
    ("COGENT", "Cogent"),
    ("GCORE", "Gcore"),
]


def _pretty_network_name(org):
    raw = (org or "").strip()

    if not raw:
        return None

    # Remove noisy BGP relationship text such as:
    # "AFRANET via AS62265 announce AS25184"
    clean = re.sub(
        r"\s+via\s+AS\d+.*$",
        "",
        raw,
        flags=re.I,
    ).strip()

    clean = re.sub(
        r"\s+announce(?:s|d)?\s+AS\d+.*$",
        "",
        clean,
        flags=re.I,
    ).strip()

    upper = clean.upper()

    for needle, label in _NETWORK_DISPLAY_NAMES:
        if needle in upper:
            return label

    # Clean a few ugly ASN-style suffixes.
    clean = re.sub(
        r"\s+-?\s*AS\d+\s*$",
        "",
        clean,
        flags=re.I,
    ).strip(" -_,")

    if not clean:
        return None

    if len(clean) > 34:
        clean = clean[:31].rstrip() + "..."

    return "Network: " + clean


def _service_from_asn(ip_text):
    info = _lookup_ip_asn(ip_text)

    if not info:
        return None

    org = (info.get("org") or "").upper()

    for needle, service, confidence in _ASN_SERVICE_RULES:
        if needle in org:
            return service, confidence

    # Owner is known, but exact app is not.
    # Show a compact provider/network name instead.
    display = _pretty_network_name(info.get("org"))

    if display:
        return display, "low"

    return None



def _detect_service(host):
    """
    Best-effort service detection from destination hostname only.
    This does NOT inspect message/page contents.
    """

    h = (host or "").lower().strip("[]").rstrip(".")

    rules = [
        (
            "ChatGPT",
            [
                "chat.openai.com",
                "android.chat.openai.com",
                "openai.com",
            ],
            "high",
        ),
        (
            "Telegram",
            [
                "telegram.org",
                "telegram.me",
                "t.me",
            ],
            "high",
        ),
        (
            "Instagram",
            [
                "instagram.com",
                "cdninstagram.com",
            ],
            "high",
        ),
        (
            "WhatsApp",
            [
                "whatsapp.com",
                "whatsapp.net",
            ],
            "high",
        ),
        (
            "YouTube",
            [
                "youtube.com",
                "googlevideo.com",
                "ytimg.com",
                "youtubei.googleapis.com",
            ],
            "high",
        ),
        (
            "Spotify",
            [
                "spotify.com",
                "scdn.co",
            ],
            "high",
        ),
        (
            "Discord",
            [
                "discord.com",
                "discord.gg",
                "discordapp.com",
            ],
            "high",
        ),
        (
            "X / Twitter",
            [
                "x.com",
                "twitter.com",
                "twimg.com",
            ],
            "high",
        ),
        (
            "TikTok",
            [
                "tiktok.com",
                "tiktokcdn.com",
                "byteoversea.com",
            ],
            "high",
        ),
        (
            "Netflix",
            [
                "netflix.com",
                "nflxvideo.net",
            ],
            "high",
        ),
        (
            "Reddit",
            [
                "reddit.com",
                "redd.it",
            ],
            "high",
        ),
        (
            "Facebook / Meta",
            [
                "facebook.com",
                "fbcdn.net",
            ],
            "high",
        ),
        (
            "GitHub",
            [
                "github.com",
                "githubusercontent.com",
            ],
            "high",
        ),
        (
            "Termius",
            [
                "termius.com",
            ],
            "high",
        ),
        (
            "Google Play",
            [
                "play.googleapis.com",
                "play-fe.googleapis.com",
            ],
            "high",
        ),
        (
            "Google Push",
            [
                "mtalk.google.com",
            ],
            "high",
        ),
        (
            "Apple / iCloud",
            [
                "icloud.com",
                "apple.com",
            ],
            "medium",
        ),
        (
            "Weather",
            [
                "weather.com",
            ],
            "high",
        ),
        (
            "Android Connectivity",
            [
                "connectivitycheck.gstatic.com",
            ],
            "high",
        ),
        (
            "App Analytics",
            [
                "sentry.io",
                "mixpanel.com",
                "split.io",
            ],
            "medium",
        ),
        (
            "Google Service",
            [
                "googleapis.com",
                "gstatic.com",
                "google.com",
            ],
            "medium",
        ),
        (
            "Cloudflare Service",
            [
                "cloudflare.com",
            ],
            "medium",
        ),
    ]

    for service, domains, confidence in rules:
        if _domain_match(h, domains):
            return service, confidence

    # Raw IP destination:
    # use local ASN database before falling back to Direct IP.
    try:
        ipaddress.ip_address(h)
        detected = _service_from_asn(h)

        if detected:
            return detected

        return "Direct IP", "low"

    except ValueError:
        pass

    return "Other Service", "low"


def _activity_age(seconds):
    seconds = max(0, int(seconds))

    if seconds < 5:
        return "now"

    if seconds < 60:
        return f"{seconds}s ago"

    if seconds < 3600:
        return f"{seconds // 60}m ago"

    return f"{seconds // 3600}h ago"


def _recent_activity_by_user():
    """
    Read recent Xray access events from systemd journal.

    Result:
      {
        "elahe": [
          {
            "service": "ChatGPT",
            "host": "android.chat.openai.com",
            ...
          }
        ]
      }
    """

    now = time.time()

    # Avoid spawning journalctl every UI refresh.
    if now - _ACTIVITY_CACHE["at"] < 4:
        return _ACTIVITY_CACHE["data"]

    try:
        proc = subprocess.run(
            [
                "journalctl",
                "-u",
                "xray",
                "--since",
                "15 minutes ago",
                "-n",
                "900",
                "-o",
                "json",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if proc.returncode != 0:
            return _ACTIVITY_CACHE["data"]

        import re

        result = {}

        pattern = re.compile(
            r"accepted\s+"
            r"(tcp|udp):"
            r"(.+):"
            r"(\d+)\s+"
            r"\[vless-cf-tunnel\b[^\]]*\]"
            r"\s+email:\s*(\S+)"
        )

        events = []

        for line in proc.stdout.splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue

            message = row.get("MESSAGE", "")
            m = pattern.search(message)

            if not m:
                continue

            protocol = m.group(1).upper()
            host = m.group(2).strip("[]")
            port = m.group(3)
            email = m.group(4)

            try:
                ts = int(
                    row.get("__REALTIME_TIMESTAMP", "0")
                ) / 1_000_000
            except Exception:
                ts = now

            age_seconds = max(0, now - ts)

            service, confidence = _detect_service(host)

            events.append({
                "email": email,
                "service": service,
                "host": host,
                "port": port,
                "protocol": protocol,
                "confidence": confidence,
                "timestamp": ts,
                "age_seconds": int(age_seconds),
                "age": _activity_age(age_seconds),
                "current": age_seconds <= 30,
            })

        # Newest first.
        events.sort(
            key=lambda x: x["timestamp"],
            reverse=True,
        )

        # Keep recent distinct services/destinations per user.
        seen = {}

        for event in events:
            email = event.pop("email")
            # One chip per service. The events are already newest-first,
            # so the newest destination wins.
            key = event["service"]

            used = seen.setdefault(email, set())

            if key in used:
                continue

            used.add(key)

            bucket = result.setdefault(email, [])

            if len(bucket) < 4:
                bucket.append(event)

        _ACTIVITY_CACHE["at"] = now
        _ACTIVITY_CACHE["data"] = result

        return result

    except Exception:
        return _ACTIVITY_CACHE["data"]


def list_users_with_activity():
    users = list_users()
    activity = _recent_activity_by_user()

    for user in users:
        name = user.get("name")
        user["activity"] = activity.get(name, [])

        current = [
            x for x in user["activity"]
            if x.get("current")
        ]

        user["current_services"] = list(
            dict.fromkeys(
                x["service"] for x in current
            )
        )

        if user["activity"]:
            user["last_destination"] = (
                user["activity"][0]["host"]
            )
        else:
            user["last_destination"] = None

    return users


# ============================================================
# VLESS_WORKER_AUTOMATION_V1
# Automatic per-user Cloudflare Workers primary + backup
# ============================================================

import vless_worker_automation as _vwa


_vwa_base_add_user = add_user
_vwa_base_delete_user = delete_user
_vwa_base_config_uri = config_uri

_vwa_config_host_lock = threading.Lock()


def _vwa_ws_path():
    cfg = _load()

    path = (
        _inbound(cfg)
        .get("streamSettings", {})
        .get("wsSettings", {})
        .get("path")
    )

    if not path:
        raise RuntimeError(
            "VLESS WebSocket path not found"
        )

    return path


def add_user(name):
    result = _vwa_base_add_user(name)

    try:
        workers = _vwa.create_pair(
            name,
            _vwa_ws_path(),
        )

    except Exception as worker_error:
        rollback_error = None

        try:
            _vwa_base_delete_user(name)

        except Exception as e:
            rollback_error = e

        if rollback_error is not None:
            raise RuntimeError(
                "Worker provisioning failed and "
                "VLESS rollback also failed: "
                f"{worker_error}; "
                f"rollback: {rollback_error}"
            )

        raise RuntimeError(
            "Worker provisioning failed; "
            "VLESS user was rolled back: "
            f"{worker_error}"
        )

    result["primary_host"] = (
        workers["primary"]
    )

    result["backup_host"] = (
        workers["backup"]
    )

    return result


def delete_user(name):
    cfg, client = _get_client(name)

    actual_name = (
        client.get("email")
        or name
    )

    # Revoke VLESS access first.
    result = _vwa_base_delete_user(
        actual_name
    )

    # Worker cleanup is best-effort. A Cloudflare outage
    # must not prevent revoking the user's VLESS credential.
    warnings = _vwa.delete_pair(
        actual_name
    )

    if warnings:
        result["worker_warning"] = (
            "; ".join(warnings)[:1000]
        )

    return result


def config_uri(name):
    # Each user's normal SlipNet config uses their own
    # PRIMARY workers.dev hostname.
    host = _vwa.primary_host(name)

    # Compatibility fallback for an old/unmapped user.
    if not host:
        return _vwa_base_config_uri(name)

    global PUBLIC_HOST

    with _vwa_config_host_lock:
        previous_host = PUBLIC_HOST
        PUBLIC_HOST = host

        try:
            return _vwa_base_config_uri(name)

        finally:
            PUBLIC_HOST = previous_host

# ============================================================
# SLIPNET_EA_V29_ALIGNMENT_V1
# Persistent usage + transactional server/client provisioning.
# ============================================================

import hashlib as _align_hashlib
import secrets as _align_secrets
from pathlib import Path as _AlignPath

_ALIGN_STATE_DIR = _AlignPath("/var/lib/slipnet-monitor")
_ALIGN_PROFILE_DIR = _ALIGN_STATE_DIR / "profiles"
_ALIGN_USAGE_FILE = _ALIGN_STATE_DIR / "vless-usage.json"
_ALIGN_REGISTRY_FILE = _ALIGN_STATE_DIR / "provisioned-users.json"
_ALIGN_USAGE_LOCK = threading.Lock()
_ALIGN_REGISTRY_LOCK = threading.Lock()

_aligned_base_add_user = add_user
_aligned_base_delete_user = delete_user


def _align_mkdirs():
    _ALIGN_STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _ALIGN_PROFILE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(_ALIGN_STATE_DIR, 0o700)
        os.chmod(_ALIGN_PROFILE_DIR, 0o700)
    except OSError:
        pass


def _align_load_json(path, default):
    try:
        with open(path, "r") as f:
            value = json.load(f)
        return value if isinstance(value, dict) else copy.deepcopy(default)
    except Exception:
        return copy.deepcopy(default)


def _align_atomic_json(path, value):
    _align_mkdirs()
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _align_registry():
    return _align_load_json(_ALIGN_REGISTRY_FILE, {"version": 1, "users": {}})


def _align_registry_set(name, data):
    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        reg.setdefault("users", {})[name.lower()] = data
        _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)


def _align_registry_pop(name):
    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        item = reg.setdefault("users", {}).pop(name.lower(), None)
        _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)
        return item


def _align_slipgate_existing_name(name):
    try:
        cfg = json.load(open("/etc/slipgate/config.json"))
    except Exception as e:
        raise RuntimeError(f"SlipGate config unavailable: {type(e).__name__}")
    wanted = name.lower()
    for user in cfg.get("users", []):
        existing = str(user.get("username") or "")
        if existing.lower() == wanted:
            return existing
    return None


def _align_slipgate_add(name):
    existing = _align_slipgate_existing_name(name)
    if existing:
        return existing, False
    if not re.fullmatch(r"[a-z0-9-]{1,32}", name):
        raise ValueError("New EA users must use lowercase letters, numbers or hyphen")
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    password = "".join(_align_secrets.choice(alphabet) for _ in range(20))
    # SlipGate's single-user `add` action still prompts for the password even
    # when a --password flag is present. Feed the generated password on stdin
    # so monitor provisioning is genuinely non-interactive. Captured output is
    # never surfaced because it contains generated credentials/configs.
    p = subprocess.run(
        [
            "/usr/local/bin/slipgate", "users",
            "--action", "add",
            "--username", name,
        ],
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "SlipGate user add failed")[-800:])
    return name, True


def _align_slipgate_remove(name):
    p = _run([
        "/usr/local/bin/slipgate", "users",
        "--action", "remove",
        "--username", name,
    ], timeout=30)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "SlipGate user remove failed")[-800:])


def _align_account_id(spec):
    raw = str(spec.get("account_id") or "").encode()
    return "cf-" + _align_hashlib.sha256(raw).hexdigest()[:16]


def _align_ech_seed(host):
    # Fetch the HTTPS/SVCB ECHConfigList on the server, never on the client.
    # Two independent recursive resolvers are tried; only syntactically valid
    # base64 payloads within the app's 8 KiB storage policy are accepted.
    for attempt in range(8):
        for resolver in ("1.1.1.1", "8.8.8.8"):
            try:
                p = _run(["dig", "+short", "HTTPS", host, "@" + resolver], timeout=8)
                if p.returncode != 0:
                    continue
                match = re.search(r'(?:^|\s)ech(?:config)?="?([^"\s]+)', p.stdout, re.I)
                if not match:
                    continue
                encoded = match.group(1).strip()
                raw = base64.b64decode(encoded + "===", validate=False)
                if 0 < len(raw) <= 8192:
                    return base64.b64encode(raw).decode("ascii")
            except Exception:
                continue
        if attempt < 7:
            time.sleep(1.5)
    raise RuntimeError("ECH bootstrap material is not available yet")


def _align_v29_uri(name, host, route_label, account_spec):
    cfg, client = _get_client(name)
    path = (
        _inbound(cfg).get("streamSettings", {})
        .get("wsSettings", {}).get("path")
    )
    if not path:
        raise RuntimeError("VLESS WebSocket path not found")
    with open(CDN_IP_FILE) as f:
        cdn_ip = f.read().strip()
    if not cdn_ip:
        raise RuntimeError("CDN IP is empty")
    email = client["email"]
    uid = client["id"]
    seed = _align_ech_seed(host)
    updated_at = str(int(time.time() * 1000))
    fields = [
        "29", "vless", f"CF-{email}-{route_label}", host, "", "0", "5000", "bbr",
        "1080", "127.0.0.1", "0", "", "", "", "0", "", "", "22", "0",
        "127.0.0.1", "0", "", "udp", "password", "", "", "", "0", "443", "",
        "", "0", "", "0", "0", "", "0", "", "0", "0", "1080", "0", "txt",
        "101", "0.0", "0", "0", "0", "0", "0", "0", "", "", "8080", "", "0",
        "/", "1", "", "", "roundrobin", "3", uid, "tls", "ws", path, cdn_ip, "443",
        "0", "micro", "100", "", "1", "1", "0", "8", "", "0", host,
        "cloudflare-workers", _align_account_id(account_spec), host, seed, updated_at,
    ]
    if len(fields) != 84:
        raise RuntimeError(f"Unexpected EA v29 profile layout: {len(fields)} fields")
    payload = "|".join(fields).encode("utf-8")
    return "slipnet://" + base64.b64encode(payload).decode("ascii")


def config_payload(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    primary = _vwa.primary_host(actual)
    backup = _vwa.backup_host(actual)
    if not primary or not backup:
        raise RuntimeError("Primary/backup Worker mapping is incomplete")
    primary_uri = _align_v29_uri(actual, primary, "Primary", _vwa.PRIMARY)
    backup_uri = _align_v29_uri(actual, backup, "Backup", _vwa.BACKUP)
    bundle = primary_uri + "\n" + backup_uri + "\n"
    _align_mkdirs()
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", actual)
    artifact = _ALIGN_PROFILE_DIR / (safe + ".slipnet")
    fd, tmp = tempfile.mkstemp(prefix=".profile-", dir=str(_ALIGN_PROFILE_DIR))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(bundle)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, artifact)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return {
        "success": True,
        "name": actual,
        "bundle": bundle,
        "primary_uri": primary_uri,
        "backup_uri": backup_uri,
        "filename": artifact.name,
        "profile_count": 2,
        "version": 29,
    }


def config_uri(name):
    # Backward-compatible API: copying the config now copies both EA routes.
    return config_payload(name)["bundle"].rstrip("\n")


def profile_artifact(name):
    payload = config_payload(name)
    path = _ALIGN_PROFILE_DIR / payload["filename"]
    return path, payload


def _align_usage_sample(cfg, stats, now):
    with _ALIGN_USAGE_LOCK:
        state = _align_load_json(_ALIGN_USAGE_FILE, {"version": 1, "users": {}})
        users = state.setdefault("users", {})
        output = []
        valid = set()
        for client in _clients(cfg):
            email = client.get("email")
            if not email:
                continue
            valid.add(email)
            raw_up = int(stats.get(f"user>>>{email}>>>traffic>>>uplink", 0) or 0)
            raw_down = int(stats.get(f"user>>>{email}>>>traffic>>>downlink", 0) or 0)
            item = users.setdefault(email, {
                "raw_up": raw_up, "raw_down": raw_down,
                "total_up": raw_up, "total_down": raw_down,
                "last_change": now if (raw_up or raw_down) else 0,
            })
            prev_up = int(item.get("raw_up", 0) or 0)
            prev_down = int(item.get("raw_down", 0) or 0)
            delta_up = raw_up - prev_up if raw_up >= prev_up else raw_up
            delta_down = raw_down - prev_down if raw_down >= prev_down else raw_down
            if delta_up or delta_down:
                item["last_change"] = now
            item["total_up"] = int(item.get("total_up", 0) or 0) + max(0, delta_up)
            item["total_down"] = int(item.get("total_down", 0) or 0) + max(0, delta_down)
            item["raw_up"] = raw_up
            item["raw_down"] = raw_down
            online_key = f"user>>>{email}>>>online"
            if online_key in stats:
                online = int(stats.get(online_key, 0) or 0) > 0
                online_source = "xray"
            else:
                changed = float(item.get("last_change", 0) or 0)
                online = bool(changed and now - changed <= 45)
                online_source = "activity"
            changed = float(item.get("last_change", 0) or 0)
            if changed:
                ago = max(0, int(now - changed))
                last_activity = f"{ago}s ago" if ago < 60 else (f"{ago // 60}m ago" if ago < 3600 else f"{ago // 3600}h ago")
            else:
                last_activity = None
            up = int(item["total_up"])
            down = int(item["total_down"])
            output.append({
                "name": email, "online": online, "online_source": online_source,
                "uplink": up, "downlink": down, "total": up + down,
                "uplink_f": _fmt_bytes(up), "downlink_f": _fmt_bytes(down),
                "total_f": _fmt_bytes(up + down), "last_activity": last_activity,
            })
        for old in list(users):
            if old not in valid:
                users.pop(old, None)
        _align_atomic_json(_ALIGN_USAGE_FILE, state)
    output.sort(key=lambda x: (not x["online"], x["name"].lower()))
    return output


def list_users():
    cfg = _load()
    stats = _stats()
    if stats is not None:
        return _align_usage_sample(cfg, stats, time.time())

    # A failed/unparseable Stats API call is not a counter reset. Preserve the
    # last durable totals and raw baselines so the next healthy sample cannot
    # double-count the same Xray bytes. Activity-log enrichment may still mark
    # a user online in list_users_with_activity().
    state = _align_load_json(_ALIGN_USAGE_FILE, {"version": 1, "users": {}})
    saved = state.get("users", {})
    out = []
    for client in _clients(cfg):
        email = client.get("email")
        if not email:
            continue
        item = saved.get(email, {})
        up = int(item.get("total_up", 0) or 0)
        down = int(item.get("total_down", 0) or 0)
        changed = float(item.get("last_change", 0) or 0)
        if changed:
            ago = max(0, int(time.time() - changed))
            last_activity = f"{ago}s ago" if ago < 60 else (f"{ago // 60}m ago" if ago < 3600 else f"{ago // 3600}h ago")
        else:
            last_activity = None
        out.append({
            "name": email, "online": False, "online_source": "stats-unavailable",
            "uplink": up, "downlink": down, "total": up + down,
            "uplink_f": _fmt_bytes(up), "downlink_f": _fmt_bytes(down),
            "total_f": _fmt_bytes(up + down), "last_activity": last_activity,
        })
    out.sort(key=lambda x: x["name"].lower())
    return out


def list_users_with_activity():
    users = list_users()
    activity = _recent_activity_by_user()
    for user in users:
        name = user.get("name")
        rows = activity.get(name, [])
        user["activity"] = rows
        current = [x for x in rows if x.get("current")]
        user["current_services"] = list(dict.fromkeys(x["service"] for x in current))
        user["last_destination"] = rows[0]["host"] if rows else None
        # Access-log activity is authoritative enough to correct the idle heuristic.
        if current:
            user["online"] = True
            user["online_source"] = "activity-log"
    return users


def _align_drop_usage(name):
    with _ALIGN_USAGE_LOCK:
        state = _align_load_json(_ALIGN_USAGE_FILE, {"version": 1, "users": {}})
        state.setdefault("users", {}).pop(name, None)
        _align_atomic_json(_ALIGN_USAGE_FILE, state)


def add_user(name):
    canonical = _validate_name(name).lower()
    if not re.fullmatch(r"[a-z0-9-]{1,32}", canonical):
        raise ValueError("New EA users must use lowercase letters, numbers or hyphen")
    result = _aligned_base_add_user(canonical)
    slipgate_name = None
    slipgate_created = False
    try:
        slipgate_name, slipgate_created = _align_slipgate_add(canonical)
        payload = config_payload(canonical)
        _align_registry_set(canonical, {
            "vless": True,
            "workers": True,
            "slipgate_name": slipgate_name,
            "slipgate_created": slipgate_created,
            "created_at": int(time.time()),
        })
        result.update({
            "profile_version": payload["version"],
            "profile_count": payload["profile_count"],
            "filename": payload["filename"],
            "slipgate_user": True,
        })
        return result
    except Exception:
        if slipgate_created and slipgate_name:
            try:
                _align_slipgate_remove(slipgate_name)
            except Exception:
                pass
        try:
            _aligned_base_delete_user(canonical)
        except Exception:
            pass
        raise


def delete_user(name):
    _, client = _get_client(name)
    actual = client.get("email") or name
    reg = _align_registry().get("users", {}).get(actual.lower())
    result = _aligned_base_delete_user(actual)
    warnings = []
    if reg and reg.get("slipgate_created") and reg.get("slipgate_name"):
        try:
            _align_slipgate_remove(reg["slipgate_name"])
        except Exception as e:
            warnings.append("SlipGate cleanup failed: " + str(e)[:300])
    _align_registry_pop(actual)
    _align_drop_usage(actual)
    try:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", actual)
        (_ALIGN_PROFILE_DIR / (safe + ".slipnet")).unlink(missing_ok=True)
    except Exception:
        pass
    if warnings:
        result["warning"] = "; ".join(warnings)
    return result



# ============================================================
# SLIPNET_EA_SUBSCRIPTION_CONTROL_V1
# Password-encrypted delivery + managed profile lock + quota/expiry.
# ============================================================

_v30_base_add_user = add_user
_v30_base_delete_user = delete_user
_v30_base_list_users = list_users


def _v30_password_hash(password):
    import hashlib
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return salt.hex() + ":" + digest


def _v30_encrypt_bundle(plaintext, password):
    if not password or len(password) < 6:
        raise ValueError("Delivery password must be at least 6 characters")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(password.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    wire = b"\x01" + salt + iv + ciphertext
    return "slipnet-bundle-enc://" + base64.b64encode(wire).decode("ascii")


def _v30_registry_update(name, changes):
    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        item = reg.setdefault("users", {}).setdefault(name.lower(), {})
        item.update(changes)
        _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)
        return copy.deepcopy(item)


def _v30_registry_item(name):
    return copy.deepcopy(
        _align_registry().get("users", {}).get((name or "").lower(), {})
    )


def _v30_lock_inner_uri(uri, lock_hash, expiration_ms, bound_device_id=""):
    if not uri.startswith("slipnet://"):
        raise RuntimeError("Unexpected inner profile scheme")
    fields = base64.b64decode(uri[len("slipnet://"):]).decode("utf-8").split("|")
    if len(fields) != 84 or fields[0] != "29":
        raise RuntimeError("Unexpected EA v29 inner profile layout")
    fields[31] = "1"                    # isLocked
    fields[32] = lock_hash              # admin-only unlock hash
    fields[33] = str(int(expiration_ms))# client-visible expiry
    fields[34] = "0"                    # allowSharing = false
    fields[35] = str(bound_device_id or "")  # device binding after enrollment
    fields[36] = "1"                    # resolver/details hidden
    fields[37] = ""
    payload = "|".join(fields).encode("utf-8")
    return "slipnet://" + base64.b64encode(payload).decode("ascii")


def _v30_plain_managed_bundle(name, lock_hash, expiration_ms, bound_device_id=""):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    primary = _vwa.primary_host(actual)
    backup = _vwa.backup_host(actual)
    if not primary or not backup:
        raise RuntimeError("Primary/backup Worker mapping is incomplete")
    p = _align_v29_uri(actual, primary, "Primary", _vwa.PRIMARY)
    b = _align_v29_uri(actual, backup, "Backup", _vwa.BACKUP)
    return (
        _v30_lock_inner_uri(
            p,
            lock_hash,
            expiration_ms,
            bound_device_id=bound_device_id,
        )
        + "\n"
        + _v30_lock_inner_uri(
            b,
            lock_hash,
            expiration_ms,
            bound_device_id=bound_device_id,
        )
        + "\n"
    )


def _v30_artifact_path(name):
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    return _ALIGN_PROFILE_DIR / (safe + ".slipnet")


def _v30_write_encrypted_artifact(name, password, lock_hash, expiration_ms):
    plain = _v30_plain_managed_bundle(name, lock_hash, expiration_ms)
    encrypted = _v30_encrypt_bundle(plain, password)
    _align_mkdirs()
    artifact = _v30_artifact_path(name)
    fd, tmp = tempfile.mkstemp(prefix=".profile-enc-", dir=str(_ALIGN_PROFILE_DIR))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(encrypted)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, artifact)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return encrypted, artifact


def add_user(name, duration_days=30, quota_bytes=0, delivery_password=""):
    canonical = _validate_name(name).lower()
    try:
        duration_days = int(duration_days)
    except Exception:
        raise ValueError("Subscription days must be an integer")
    try:
        quota_bytes = int(quota_bytes)
    except Exception:
        raise ValueError("Traffic quota is invalid")
    if duration_days < 0 or duration_days > 3650:
        raise ValueError("Subscription days must be between 0 and 3650")
    if quota_bytes < 0:
        raise ValueError("Traffic quota cannot be negative")
    if not delivery_password or len(delivery_password) < 6:
        raise ValueError("Delivery password must be at least 6 characters")

    result = _aligned_base_add_user(canonical)
    slipgate_name = None
    slipgate_created = False
    created_at = int(time.time())
    expires_at = created_at + duration_days * 86400 if duration_days else 0
    expiration_ms = expires_at * 1000 if expires_at else 0
    admin_unlock_secret = _align_secrets.token_urlsafe(32)
    lock_hash = _v30_password_hash(admin_unlock_secret)

    try:
        slipgate_name, slipgate_created = _align_slipgate_add(canonical)
        encrypted, artifact = _v30_write_encrypted_artifact(
            canonical, delivery_password, lock_hash, expiration_ms
        )
        _align_registry_set(canonical, {
            "vless": True,
            "workers": True,
            "slipgate_name": slipgate_name,
            "slipgate_created": slipgate_created,
            "created_at": created_at,
            "expires_at": expires_at,
            "quota_bytes": quota_bytes,
            "delivery_password_hash": _v30_password_hash(delivery_password),
            "profile_lock_hash": lock_hash,
            "access_state": "active",
            "artifact": artifact.name,
            "managed_profile": True,
        })
        result.update({
            "profile_version": 29,
            "profile_count": 2,
            "filename": artifact.name,
            "slipgate_user": True,
            "encrypted_delivery": True,
            "expires_at": expires_at,
            "quota_bytes": quota_bytes,
        })
        return result
    except Exception:
        if slipgate_created and slipgate_name:
            try:
                _align_slipgate_remove(slipgate_name)
            except Exception:
                pass
        try:
            _aligned_base_delete_user(canonical)
        except Exception:
            pass
        try:
            _align_registry_pop(canonical)
        except Exception:
            pass
        try:
            _v30_artifact_path(canonical).unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _v30_limits_for(name):
    item = _v30_registry_item(name)
    return {
        "created_at": int(item.get("created_at", 0) or 0),
        "expires_at": int(item.get("expires_at", 0) or 0),
        "quota_bytes": int(item.get("quota_bytes", 0) or 0),
        "access_state": str(item.get("access_state") or "active"),
        "managed_profile": bool(item.get("managed_profile")),
    }


def _v30_enforce_access(user):
    name = user.get("name") or ""
    meta = _v30_limits_for(name)
    now = int(time.time())
    total = int(user.get("total", 0) or 0)
    expired = bool(meta["expires_at"] and now >= meta["expires_at"])
    quota_hit = bool(meta["quota_bytes"] and total >= meta["quota_bytes"])
    blocked = expired or quota_hit

    if blocked:
        reason = "expired" if expired else "quota"
        try:
            _runtime_remove(name)
        except Exception:
            pass
        if meta["access_state"] != reason:
            _v30_registry_update(name, {"access_state": reason})
        user["online"] = False
        user["access_state"] = reason
    else:
        if meta["access_state"] in ("expired", "quota"):
            runtime_ready = False
            try:
                cfg, client = _get_client(name)
                _runtime_add(client, cfg)
                runtime_ready = True
            except Exception as error:
                # Xray reports an already-present user as a non-zero CLI error.
                # That state is still ready; every other failure must remain
                # fail-closed instead of being mislabeled active.
                if "already exists" in str(error).lower():
                    runtime_ready = True
            if runtime_ready:
                _v30_registry_update(name, {"access_state": "active"})
                user["access_state"] = "active"
            else:
                user["online"] = False
                user["access_state"] = meta["access_state"]
        else:
            user["access_state"] = "active"

    user["created_at"] = meta["created_at"]
    user["expires_at"] = meta["expires_at"]
    user["quota_bytes"] = meta["quota_bytes"]
    user["quota_f"] = _fmt_bytes(meta["quota_bytes"]) if meta["quota_bytes"] else "Unlimited"
    user["remaining_bytes"] = max(0, meta["quota_bytes"] - total) if meta["quota_bytes"] else 0
    user["remaining_f"] = _fmt_bytes(user["remaining_bytes"]) if meta["quota_bytes"] else "Unlimited"
    user["days_left"] = (
        max(0, (meta["expires_at"] - now + 86399) // 86400)
        if meta["expires_at"] else None
    )
    user["managed_profile"] = meta["managed_profile"]
    return user


def list_users():
    users = _v30_base_list_users()
    return [_v30_enforce_access(u) for u in users]


def list_users_with_activity():
    users = list_users()
    activity = _recent_activity_by_user()
    for user in users:
        name = user.get("name")
        rows = activity.get(name, [])
        user["activity"] = rows
        current = [x for x in rows if x.get("current")]
        user["current_services"] = list(dict.fromkeys(x["service"] for x in current))
        user["last_destination"] = rows[0]["host"] if rows else None
        if current and user.get("access_state") == "active":
            user["online"] = True
            user["online_source"] = "activity-log"
    return users


def subscription_usage_for_token(token):
    import hmac

    token = str(token or "").strip().lower()
    if len(token) != 36:
        raise PermissionError("Invalid subscription token")

    matched_name = None
    for client in _clients(_load()):
        client_id = str(client.get("id") or "").strip().lower()
        if client_id and hmac.compare_digest(client_id, token):
            matched_name = str(client.get("email") or "").strip()
            break

    if not matched_name:
        raise PermissionError("Invalid subscription token")

    user = next(
        (
            item for item in list_users()
            if str(item.get("name") or "").lower() == matched_name.lower()
        ),
        None,
    )
    if user is None:
        raise RuntimeError("Subscription usage is unavailable")

    return {
        "success": True,
        "bytes_sent": int(user.get("uplink", 0) or 0),
        "bytes_received": int(user.get("downlink", 0) or 0),
        "total_bytes": int(user.get("total", 0) or 0),
        "quota_bytes": int(user.get("quota_bytes", 0) or 0),
        "remaining_bytes": int(user.get("remaining_bytes", 0) or 0),
        "created_at": int(user.get("created_at", 0) or 0),
        "expires_at": int(user.get("expires_at", 0) or 0),
        "days_left": user.get("days_left"),
        "access_state": str(user.get("access_state") or "active"),
    }


def config_payload(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    path = _v30_artifact_path(actual)
    if not path.exists():
        raise RuntimeError("Encrypted delivery artifact is missing; rotate the delivery password")
    encrypted = path.read_text().strip()
    if not encrypted.startswith("slipnet-bundle-enc://"):
        raise RuntimeError("Refusing to expose a plaintext profile artifact")
    meta = _v30_limits_for(actual)
    return {
        "success": True,
        "name": actual,
        "bundle": encrypted,
        "uri": encrypted,
        "filename": path.name,
        "profile_count": 2,
        "version": 29,
        "encrypted_delivery": True,
        "expires_at": meta["expires_at"],
        "quota_bytes": meta["quota_bytes"],
    }


def config_uri(name):
    return config_payload(name)["bundle"]


def profile_artifact(name):
    payload = config_payload(name)
    path = _v30_artifact_path(payload["name"])
    return path, payload


def rotate_delivery_password(name, delivery_password):
    raise RuntimeError(
        "Legacy delivery-password artifacts are disabled; use Reset Device to issue a one-time enrollment file"
    )


def update_user_limits(name, duration_days=None, quota_bytes=None, reset_usage=False):
    _, client = _get_client(name)
    actual = client.get("email") or name
    meta = _v30_registry_item(actual)
    changes = {}
    now = int(time.time())

    if duration_days is not None:
        duration_days = int(duration_days)
        if duration_days < 0 or duration_days > 3650:
            raise ValueError("Subscription days must be between 0 and 3650")
        changes["expires_at"] = now + duration_days * 86400 if duration_days else 0

    if quota_bytes is not None:
        quota_bytes = int(quota_bytes)
        if quota_bytes < 0:
            raise ValueError("Traffic quota cannot be negative")
        changes["quota_bytes"] = quota_bytes

    if reset_usage:
        reset_user_usage(actual)

    # Preserve the current access_state until enforcement reconciles the new
    # limits. This matters when a quota/expired user was already removed from
    # Xray runtime: _v30_enforce_access() must still see the blocked state so it
    # can add the user back before flipping the registry to active.
    item = _v30_registry_update(actual, changes)
    reconciled = next(
        (u for u in list_users() if (u.get("name") or "").lower() == actual.lower()),
        None,
    )
    if reconciled is None:
        raise RuntimeError("User disappeared during limit reconciliation")
    if reconciled.get("access_state") != "active":
        raise RuntimeError(
            "Limits were updated but Xray runtime access could not be re-enabled"
        )

    # Runtime/server limits are authoritative. Existing redeemed profiles
    # continue to use server authority. If a fresh client-visible artifact is
    # needed, Reset Device rotates the credential and issues a new one-time file.
    return {
        "success": True,
        "name": actual,
        "expires_at": int(reconciled.get("expires_at", 0) or 0),
        "quota_bytes": int(reconciled.get("quota_bytes", 0) or 0),
        "access_state": reconciled.get("access_state", "active"),
    }


def reset_user_usage(name):
    _, client = _get_client(name)
    actual = client.get("email") or name
    stats = _stats() or {}
    raw_up = int(stats.get(f"user>>>{actual}>>>traffic>>>uplink", 0) or 0)
    raw_down = int(stats.get(f"user>>>{actual}>>>traffic>>>downlink", 0) or 0)
    with _ALIGN_USAGE_LOCK:
        state = _align_load_json(_ALIGN_USAGE_FILE, {"version": 1, "users": {}})
        state.setdefault("users", {})[actual] = {
            "raw_up": raw_up,
            "raw_down": raw_down,
            "total_up": 0,
            "total_down": 0,
            "last_change": 0,
        }
        _align_atomic_json(_ALIGN_USAGE_FILE, state)
    _v30_registry_update(actual, {"access_state": "active"})
    return {"success": True, "name": actual}


# ============================================================
# SLIPNET_EA_ONE_TIME_ENROLLMENT
# v1: legacy two-phase redeem; v2: challenge -> redeem -> complete.
# One-time delivery token + Android Keystore public-key binding.
# ============================================================

import hmac as _v31_hmac
from cryptography.hazmat.primitives import hashes as _v31_hashes
from cryptography.hazmat.primitives import serialization as _v31_serialization
from cryptography.hazmat.primitives.asymmetric import ec as _v31_ec
from cryptography.exceptions import InvalidSignature as _V31InvalidSignature

_V31_ENROLLMENT_SCHEME = "slipnet-enroll://"
_V31_ENROLLMENT_URL = os.environ.get(
    "SLIPNET_ENROLLMENT_URL",
    "https://monitor.cspf.shop/api/enrollment/redeem",
).strip()
_V31_ENROLLMENT_TTL_SECONDS = int(
    os.environ.get("SLIPNET_ENROLLMENT_TTL_SECONDS", str(30 * 86400))
)
_V31_CHALLENGE_TTL_SECONDS = int(
    os.environ.get("SLIPNET_ENROLLMENT_CHALLENGE_TTL_SECONDS", "300")
)
_V31_ENROLLMENT_PROTOCOL_VERSION = 2
_V31_REISSUE_LOCK = threading.Lock()

_v31_base_add_user = add_user
_v31_base_delete_user = delete_user
_v31_base_list_users = list_users
_v31_base_config_payload = config_payload
_v31_base_profile_artifact = profile_artifact


class EnrollmentAlreadyUsedError(Exception):
    pass


def _v31_token_hash(token):
    return _align_hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def _v31_b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _v31_enrollment_urls(name):
    hosts = [
        _vwa.primary_host(name),
        _vwa.backup_host(name),
    ]
    urls = []
    for host in hosts:
        host = str(host or "").strip().lower()
        if host and host not in {url.split("://", 1)[1].split("/", 1)[0] for url in urls}:
            urls.append(f"https://{host}/api/enrollment/redeem")
    if not urls:
        if not _V31_ENROLLMENT_URL.startswith("https://"):
            raise RuntimeError("Enrollment URL must use HTTPS")
        urls.append(_V31_ENROLLMENT_URL)
    return urls


def _v31_enrollment_uri(
    name,
    token,
    protocol_version=_V31_ENROLLMENT_PROTOCOL_VERSION,
):
    if protocol_version not in (1, 2):
        raise ValueError("Unsupported enrollment protocol version")
    urls = _v31_enrollment_urls(name)
    body = {
        "v": protocol_version,
        "name": name,
        "url": urls[0],
        "token": token,
    }
    if len(urls) > 1:
        body["backup_url"] = urls[1]
    encoded = json.dumps(
        body,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _V31_ENROLLMENT_SCHEME + _v31_b64url_encode(encoded)


def _v31_write_enrollment_artifact(name, uri):
    _align_mkdirs()
    artifact = _v30_artifact_path(name)
    fd, tmp = tempfile.mkstemp(prefix=".profile-enroll-", dir=str(_ALIGN_PROFILE_DIR))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(uri)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, artifact)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return artifact


def _v31_issue_enrollment(name, refresh_workers=True):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    if refresh_workers:
        _vwa.refresh_pair(actual, _vwa_ws_path())
    token = _align_secrets.token_urlsafe(32)
    now = int(time.time())
    protocol_version = _V31_ENROLLMENT_PROTOCOL_VERSION
    uri = _v31_enrollment_uri(
        actual,
        token,
        protocol_version=protocol_version,
    )
    artifact = _v31_write_enrollment_artifact(actual, uri)
    _v30_registry_update(actual, {
        "artifact": artifact.name,
        "managed_profile": True,
        "delivery_password_hash": "",
        "enrollment_protocol_version": protocol_version,
        "enrollment_state": "unused",
        "enrollment_token_hash": _v31_token_hash(token),
        "enrollment_created_at": now,
        "enrollment_expires_at": now + _V31_ENROLLMENT_TTL_SECONDS,
        "enrollment_bundle_issued_at": 0,
        "enrollment_redeemed_at": 0,
        "bound_device_id": "",
        "bound_device_key_sha256": "",
        "enrollment_challenge_hash": "",
        "enrollment_challenge_expires_at": 0,
    })
    return {
        "success": True,
        "name": actual,
        "uri": uri,
        "bundle": uri,
        "filename": artifact.name,
        "profile_count": 2,
        "version": protocol_version,
        "one_time_enrollment": True,
        "enrollment_state": "unused",
        "enrollment_expires_at": now + _V31_ENROLLMENT_TTL_SECONDS,
    }


def _v31_decode_device_identity(token, device_id, public_key_b64):
    token = str(token or "").strip()
    device_id = str(device_id or "").strip().lower()
    if len(token) < 32 or len(token) > 256:
        raise PermissionError("Invalid enrollment token")
    if not re.fullmatch(r"[0-9a-f]{16}", device_id):
        raise ValueError("Invalid device identifier")

    try:
        public_der = base64.b64decode(public_key_b64, validate=True)
        public_key = _v31_serialization.load_der_public_key(public_der)
    except Exception:
        raise ValueError("Invalid device key material")

    if not isinstance(public_key, _v31_ec.EllipticCurvePublicKey):
        raise ValueError("Unsupported device key type")
    if not isinstance(public_key.curve, _v31_ec.SECP256R1):
        raise ValueError("Unsupported device key curve")

    key_sha256 = _align_hashlib.sha256(public_der).hexdigest()
    return token, device_id, key_sha256, public_key


def _v31_find_enrollment(reg, digest):
    for username, item in reg.setdefault("users", {}).items():
        stored = str(item.get("enrollment_token_hash") or "")
        if stored and _v31_hmac.compare_digest(stored, digest):
            return username, item
    raise PermissionError("Invalid enrollment token")


def _v31_protocol_version(item):
    raw = item.get("enrollment_protocol_version", 1)
    try:
        version = int(raw)
    except Exception:
        raise PermissionError("Invalid enrollment protocol version")
    if version not in (1, 2):
        raise PermissionError("Unsupported enrollment protocol version")
    return version


def _v31_validate_enrollment_window(item, now):
    subscription_expires = int(item.get("expires_at", 0) or 0)
    if subscription_expires and now >= subscription_expires:
        raise PermissionError("Subscription expired")
    enrollment_expires = int(item.get("enrollment_expires_at", 0) or 0)
    if enrollment_expires and now >= enrollment_expires:
        raise PermissionError("Enrollment file expired")


def _v31_require_same_device(item, device_id, key_sha256):
    same_device = (
        str(item.get("bound_device_id") or "") == device_id
        and _v31_hmac.compare_digest(
            str(item.get("bound_device_key_sha256") or ""),
            key_sha256,
        )
    )
    if not same_device:
        raise EnrollmentAlreadyUsedError(
            "This one-time configuration is already activated on another device"
        )


def issue_enrollment_challenge(token, device_id, public_key_b64):
    token, device_id, key_sha256, _ = _v31_decode_device_identity(
        token, device_id, public_key_b64
    )
    digest = _v31_token_hash(token)
    now = int(time.time())
    challenge = _align_secrets.token_urlsafe(32)

    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        actual, item = _v31_find_enrollment(reg, digest)
        _v31_validate_enrollment_window(item, now)
        protocol_version = _v31_protocol_version(item)
        state = str(item.get("enrollment_state") or "")

        if state == "unused":
            item["enrollment_state"] = "pending"
            item["bound_device_id"] = device_id
            item["bound_device_key_sha256"] = key_sha256
        elif state == "pending":
            _v31_require_same_device(item, device_id, key_sha256)
        elif state == "redeemed":
            if protocol_version < 2:
                raise EnrollmentAlreadyUsedError(
                    "This one-time configuration has already been used"
                )
            # v2 completion is idempotent: the same bound device may request a
            # fresh proof challenge to finish cleanup after a lost response.
            _v31_require_same_device(item, device_id, key_sha256)
        else:
            raise PermissionError("Enrollment is not active")

        item["enrollment_challenge_hash"] = _v31_token_hash(challenge)
        item["enrollment_challenge_expires_at"] = now + _V31_CHALLENGE_TTL_SECONDS
        _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)

    return {
        "success": True,
        "name": actual,
        "challenge": challenge,
        "challenge_expires_at": now + _V31_CHALLENGE_TTL_SECONDS,
        "enrollment_state": "pending" if state == "unused" else state,
    }


def _v31_decode_signed_proof(signature_b64):
    try:
        return base64.b64decode(signature_b64, validate=True)
    except Exception:
        raise ValueError("Invalid device signature")


def _v31_verify_signed_challenge(
    item,
    token,
    device_id,
    key_sha256,
    public_key,
    challenge,
    signature,
    claim_version,
    now,
):
    challenge = str(challenge or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", challenge):
        raise ValueError("Invalid enrollment challenge")

    _v31_require_same_device(item, device_id, key_sha256)

    stored_challenge_hash = str(item.get("enrollment_challenge_hash") or "")
    challenge_expires = int(item.get("enrollment_challenge_expires_at", 0) or 0)
    if not stored_challenge_hash or challenge_expires <= now:
        raise PermissionError("Enrollment challenge expired")
    if not _v31_hmac.compare_digest(
        stored_challenge_hash,
        _v31_token_hash(challenge),
    ):
        raise PermissionError("Invalid enrollment challenge")

    message = (
        claim_version + "\n"
        + token + "\n"
        + device_id + "\n"
        + challenge
    ).encode("utf-8")
    try:
        public_key.verify(
            signature,
            message,
            _v31_ec.ECDSA(_v31_hashes.SHA256()),
        )
    except _V31InvalidSignature:
        raise PermissionError("Invalid device proof")


def redeem_enrollment(token, device_id, public_key_b64, challenge, signature_b64):
    token, device_id, key_sha256, public_key = _v31_decode_device_identity(
        token, device_id, public_key_b64
    )
    signature = _v31_decode_signed_proof(signature_b64)

    digest = _v31_token_hash(token)
    now = int(time.time())
    actual = None
    lock_hash = None
    expires_at = 0

    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        actual, item = _v31_find_enrollment(reg, digest)
        _v31_validate_enrollment_window(item, now)
        protocol_version = _v31_protocol_version(item)
        state = str(item.get("enrollment_state") or "")

        if state == "redeemed":
            raise EnrollmentAlreadyUsedError(
                "This one-time configuration has already been used"
            )
        if state != "pending":
            raise PermissionError("Enrollment challenge is required")

        _v31_verify_signed_challenge(
            item,
            token,
            device_id,
            key_sha256,
            public_key,
            challenge,
            signature,
            "slipnet-enroll-challenge-v1",
            now,
        )

        if not int(item.get("enrollment_bundle_issued_at", 0) or 0):
            item["enrollment_bundle_issued_at"] = now
        if protocol_version == 1:
            item["enrollment_state"] = "redeemed"
            if not int(item.get("enrollment_redeemed_at", 0) or 0):
                item["enrollment_redeemed_at"] = now
        lock_hash = str(item.get("profile_lock_hash") or "")
        expires_at = int(item.get("expires_at", 0) or 0)
        _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)

    if not lock_hash:
        raise RuntimeError("Managed profile lock identity is missing")

    bundle = _v30_plain_managed_bundle(
        actual,
        lock_hash,
        expires_at * 1000 if expires_at else 0,
        bound_device_id=device_id,
    )
    return {
        "success": True,
        "name": actual,
        "bundle": bundle,
        "profile_count": 2,
        "profile_version": 29,
        "device_bound": True,
        "device_id": device_id,
        "enrollment_protocol_version": protocol_version,
        "enrollment_state": (
            "redeemed" if protocol_version == 1 else "pending"
        ),
    }


def complete_enrollment(token, device_id, public_key_b64, challenge, signature_b64):
    token, device_id, key_sha256, public_key = _v31_decode_device_identity(
        token, device_id, public_key_b64
    )
    signature = _v31_decode_signed_proof(signature_b64)

    digest = _v31_token_hash(token)
    now = int(time.time())

    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        actual, item = _v31_find_enrollment(reg, digest)
        _v31_validate_enrollment_window(item, now)
        protocol_version = _v31_protocol_version(item)
        if protocol_version < 2:
            raise PermissionError(
                "Enrollment protocol does not require completion"
            )
        state = str(item.get("enrollment_state") or "")

        if state not in ("pending", "redeemed"):
            raise PermissionError("Enrollment is not ready for completion")

        _v31_verify_signed_challenge(
            item,
            token,
            device_id,
            key_sha256,
            public_key,
            challenge,
            signature,
            "slipnet-enroll-complete-v1",
            now,
        )

        if state == "pending":
            if not int(item.get("enrollment_bundle_issued_at", 0) or 0):
                raise PermissionError(
                    "Enrollment bundle must be issued before completion"
                )
            item["enrollment_state"] = "redeemed"
            if not int(item.get("enrollment_redeemed_at", 0) or 0):
                item["enrollment_redeemed_at"] = now
            _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)

    return {
        "success": True,
        "name": actual,
        "device_bound": True,
        "device_id": device_id,
        "enrollment_state": "redeemed",
    }


def _v31_replace_vless_uuid(name, replacement_uuid, snapshot_usage=True):
    if snapshot_usage:
        # Snapshot current raw counters into durable totals before Xray runtime
        # removes/re-adds the email and potentially resets raw per-user counters.
        _v31_base_list_users()

    meta = _v30_registry_item(name)
    if str(meta.get("access_state") or "active") != "active":
        raise RuntimeError("Reset Device requires an active subscription")

    try:
        replacement_uuid = str(uuidlib.UUID(str(replacement_uuid)))
    except Exception:
        raise ValueError("Replacement VLESS UUID is invalid")

    with LOCK:
        cfg = _load()
        clients = _clients(cfg)
        index = None
        old_client = None
        for i, client in enumerate(clients):
            if str(client.get("email") or "").lower() == name.lower():
                index = i
                old_client = copy.deepcopy(client)
                break
        if old_client is None:
            raise ValueError("User not found")

        old_uuid = str(old_client.get("id") or "")
        if old_uuid == replacement_uuid:
            return old_uuid, replacement_uuid

        new_client = copy.deepcopy(old_client)
        new_client["id"] = replacement_uuid
        new_cfg = copy.deepcopy(cfg)
        _clients(new_cfg)[index] = copy.deepcopy(new_client)
        _validate_config(new_cfg)

        _runtime_remove(old_client.get("email") or name)
        new_runtime_added = False
        try:
            _runtime_add(new_client, cfg)
            new_runtime_added = True
            _persist(new_cfg)
        except Exception as exc:
            rollback_errors = []
            if new_runtime_added:
                try:
                    _runtime_remove(new_client.get("email") or name)
                except Exception as rollback_exc:
                    rollback_errors.append("remove-new: " + str(rollback_exc))
            try:
                _runtime_add(old_client, cfg)
            except Exception as rollback_exc:
                rollback_errors.append("restore-old: " + str(rollback_exc))
            if rollback_errors:
                raise RuntimeError(
                    "VLESS credential replacement failed and runtime rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from exc
            raise

    return old_uuid, replacement_uuid


def _v31_rotate_vless_uuid(name):
    old_uuid, new_uuid = _v31_replace_vless_uuid(
        name,
        str(uuidlib.uuid4()),
        snapshot_usage=True,
    )
    return old_uuid, new_uuid


def _v31_snapshot_reissue_state(name):
    meta = _v30_registry_item(name)
    artifact = _v30_artifact_path(name)
    if artifact.exists():
        return meta, artifact.read_bytes(), artifact.stat().st_mode & 0o777
    return meta, None, None


def _v31_restore_reissue_state(name, meta, artifact_bytes, artifact_mode):
    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        users = reg.setdefault("users", {})
        key = name.lower()
        if meta:
            users[key] = copy.deepcopy(meta)
        else:
            users.pop(key, None)
        _align_atomic_json(_ALIGN_REGISTRY_FILE, reg)

    artifact = _v30_artifact_path(name)
    if artifact_bytes is None:
        artifact.unlink(missing_ok=True)
        return

    _align_mkdirs()
    fd, tmp = tempfile.mkstemp(
        prefix=".profile-rollback-",
        dir=str(_ALIGN_PROFILE_DIR),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(artifact_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, artifact_mode or 0o600)
        os.replace(tmp, artifact)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def reissue_enrollment(name):
    with _V31_REISSUE_LOCK:
        _, client = _get_client(name)
        actual = client.get("email") or _validate_name(name)
        meta = _v30_registry_item(actual)

        if str(meta.get("access_state") or "active") != "active":
            raise RuntimeError("Reset Device requires an active subscription")

        previous_meta, previous_artifact, previous_mode = (
            _v31_snapshot_reissue_state(actual)
        )

        # Preflight and refresh the complete pair before revoking the working
        # credential. A missing or unhealthy Primary/Backup pair must fail
        # while the old credential is still untouched.
        _vwa.refresh_pair(actual, _vwa_ws_path())

        rotated = False
        rollback_uuid = None
        try:
            # Legacy users may predate the managed-profile registry entirely.
            # Seed one-time lock metadata only inside the transaction so it can
            # be restored exactly if any later step fails.
            if not meta.get("profile_lock_hash"):
                _v30_registry_update(actual, {
                    "managed_profile": True,
                    "profile_lock_hash": _v30_password_hash(
                        _align_secrets.token_urlsafe(32)
                    ),
                    "created_at": int(meta.get("created_at", 0) or int(time.time())),
                    "expires_at": int(meta.get("expires_at", 0) or 0),
                    "quota_bytes": int(meta.get("quota_bytes", 0) or 0),
                    "access_state": str(meta.get("access_state") or "active"),
                })

            rollback_uuid, _ = _v31_rotate_vless_uuid(actual)
            rotated = True

            # Workers were already refreshed and health-checked above. Do not
            # repeat external mutation after revoking the old credential.
            result = _v31_issue_enrollment(
                actual,
                refresh_workers=False,
            )
            result["credential_rotated"] = True
            return result

        except Exception as exc:
            rollback_errors = []

            if rotated and rollback_uuid:
                try:
                    _v31_replace_vless_uuid(
                        actual,
                        rollback_uuid,
                        snapshot_usage=False,
                    )
                except Exception as rollback_exc:
                    rollback_errors.append(
                        "credential: " + str(rollback_exc)
                    )

            try:
                _v31_restore_reissue_state(
                    actual,
                    previous_meta,
                    previous_artifact,
                    previous_mode,
                )
            except Exception as rollback_exc:
                rollback_errors.append(
                    "enrollment-state: " + str(rollback_exc)
                )

            if rollback_errors:
                raise RuntimeError(
                    "Reset Device failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from exc
            raise


def add_user(name, duration_days=30, quota_bytes=0, delivery_password=""):
    # v31 delivery never ships a reusable VLESS bundle. v30 still needs a
    # password internally while provisioning, so generate an unshared one.
    internal_password = delivery_password or _align_secrets.token_urlsafe(24)
    result = _v31_base_add_user(
        name,
        duration_days=duration_days,
        quota_bytes=quota_bytes,
        delivery_password=internal_password,
    )
    try:
        enrollment = _v31_issue_enrollment(result["name"], refresh_workers=False)
    except Exception:
        try:
            _v31_base_delete_user(result["name"])
        except Exception:
            pass
        raise
    result.update({
        "one_time_enrollment": True,
        "encrypted_delivery": False,
        "filename": enrollment["filename"],
        "enrollment_state": enrollment["enrollment_state"],
        "enrollment_expires_at": enrollment["enrollment_expires_at"],
    })
    return result


def list_users():
    users = _v31_base_list_users()
    registry = _align_registry().get("users", {})
    for user in users:
        item = registry.get(str(user.get("name") or "").lower(), {})
        state = str(item.get("enrollment_state") or "legacy")
        user["enrollment_state"] = state
        user["enrollment_protocol_version"] = (
            _v31_protocol_version(item)
            if item.get("enrollment_token_hash")
            else 0
        )
        user["device_bound"] = bool(item.get("bound_device_key_sha256"))
        user["enrollment_redeemed_at"] = int(item.get("enrollment_redeemed_at", 0) or 0)
        user["enrollment_expires_at"] = int(item.get("enrollment_expires_at", 0) or 0)
    return users


def config_payload(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    meta = _v30_registry_item(actual)
    if not meta.get("managed_profile"):
        raise RuntimeError(
            "Legacy user has no one-time binding; use Reset Device to revoke the old credential and issue a one-time file"
        )

    state = str(meta.get("enrollment_state") or "")
    path = _v30_artifact_path(actual)
    if not state:
        raise RuntimeError(
            "Legacy user has no one-time binding; use Reset Device to revoke the old credential and issue a one-time file"
        )

    access_state = str(meta.get("access_state") or "active")
    if access_state != "active":
        raise RuntimeError("Subscription is not active")

    if state == "redeemed":
        raise RuntimeError("Enrollment already activated; use Reset Device to issue a new one-time file")
    if state != "unused":
        raise RuntimeError("Enrollment is not available")

    enrollment_expires_at = int(meta.get("enrollment_expires_at", 0) or 0)
    if enrollment_expires_at and int(time.time()) >= enrollment_expires_at:
        return _v31_issue_enrollment(actual)

    if not path.exists():
        return _v31_issue_enrollment(actual)
    uri = path.read_text().strip()
    if not uri.startswith(_V31_ENROLLMENT_SCHEME):
        return _v31_issue_enrollment(actual)

    return {
        "success": True,
        "name": actual,
        "bundle": uri,
        "uri": uri,
        "filename": path.name,
        "profile_count": 2,
        "version": _v31_protocol_version(meta),
        "one_time_enrollment": True,
        "enrollment_state": "unused",
        "enrollment_expires_at": int(meta.get("enrollment_expires_at", 0) or 0),
    }


def config_uri(name):
    return config_payload(name)["uri"]


def profile_artifact(name):
    payload = config_payload(name)
    return _v30_artifact_path(payload["name"]), payload


# ============================================================
# SLIPNET_DIRECT_ROUTE_ADMIN_V1
# Provider-direct routes are delivered separately from the
# strict two-profile managed enrollment pair. This preserves
# compatibility with the existing Android enrollment validator.
# ============================================================

import direct_routes as _direct_routes


def _direct_v29_uri(name, route):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    uid = client["id"]

    host = str(route["host"])
    path = str(route["path"])
    port = int(route.get("port", 443))
    route_id = str(route["id"])
    provider = str(route.get("provider") or "direct")
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", str(route.get("label") or route_id)).strip("-")

    # Direct provider routes intentionally use the existing fragmentation
    # transport, not ECH. This keeps them separate from the managed
    # Cloudflare Worker failure-domain pair and requires no client change.
    fields = [
        "29", "vless", f"DIRECT-{actual}-{label}", host, "", "0", "5000", "bbr",
        "1080", "127.0.0.1", "0", "", "", "", "0", "", "", "22", "0",
        "127.0.0.1", "0", "", "udp", "password", "", "", "", "0", "443", "",
        "", "0", "", "0", "0", "", "0", "", "0", "0", "1080", "0", "txt",
        "101", "0.0", "0", "0", "0", "0", "0", "0", "", "", "8080", "", "0",
        "/", "1", "", "", "roundrobin", "3", uid, "tls", "ws", path,
        host, str(port),
        "1", "sni_split", "100", "", "0", "0", "0", "8", "", "0", host,
        "", "", "", "", "0",
    ]
    if len(fields) != 84:
        raise RuntimeError(f"Unexpected direct v29 profile layout: {len(fields)} fields")
    payload = "|".join(fields).encode("utf-8")
    return "slipnet://" + base64.b64encode(payload).decode("ascii")


def direct_route_summary(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    summary = _direct_routes.user_summary(actual)
    meta = _v30_registry_item(actual)
    summary["device_bound"] = bool(meta.get("bound_device_id"))
    summary["access_state"] = str(meta.get("access_state") or "active")
    summary["enrollment_state"] = str(meta.get("enrollment_state") or "legacy")
    return summary


def set_direct_routes(name, route_ids):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    result = _direct_routes.set_user_routes(actual, route_ids)
    result["apply_on_next_download"] = True
    return result


def set_direct_route_enabled(route_id, enabled):
    return _direct_routes.set_route_enabled(route_id, enabled)


def list_direct_routes():
    return {
        "success": True,
        "routes": _direct_routes.list_routes(include_private=False),
    }


def direct_config_payload(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    meta = _v30_registry_item(actual)

    if str(meta.get("access_state") or "active") != "active":
        raise RuntimeError("Subscription is not active")

    if not meta.get("managed_profile"):
        raise RuntimeError("User is not managed by the current EA subscription authority")

    routes = _direct_routes.routes_for_user(actual)
    if not routes:
        raise RuntimeError("No enabled direct routes are assigned to this user")

    lock_hash = str(meta.get("profile_lock_hash") or "")
    if not lock_hash:
        raise RuntimeError("Managed profile lock identity is missing")

    expires_at = int(meta.get("expires_at", 0) or 0)
    expiration_ms = expires_at * 1000 if expires_at else 0
    bound_device_id = str(meta.get("bound_device_id") or "")

    uris = []
    route_ids = []
    for route in routes:
        uri = _direct_v29_uri(actual, route)
        uri = _v30_lock_inner_uri(
            uri,
            lock_hash,
            expiration_ms,
            bound_device_id=bound_device_id,
        )
        uris.append(uri)
        route_ids.append(route["id"])

    bundle = "\n".join(uris) + "\n"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", actual)

    return {
        "success": True,
        "name": actual,
        "bundle": bundle,
        "filename": safe + ".direct.slipnet",
        "profile_count": len(uris),
        "profile_version": 29,
        "route_ids": route_ids,
        "device_bound": bool(bound_device_id),
    }


def direct_profile_artifact(name):
    # Compatibility helper: Direct bundles are generated in memory and are
    # intentionally not persisted as plaintext artifacts on the server.
    payload = direct_config_payload(name)
    return payload["bundle"].encode("utf-8"), payload


_direct_routes_base_delete_user = delete_user


def delete_user(name):
    _, client = _get_client(name)
    actual = client.get("email") or name
    result = _direct_routes_base_delete_user(actual)
    try:
        _direct_routes.drop_user(actual)
    except Exception as exc:
        result["direct_route_warning"] = str(exc)[:300]
    return result


# ============================================================
# DIRECT_XRAY_MEMBERSHIP_V2
# Route assignment is enforced in Xray, not just in the UI.
# Each provider-direct route owns a dedicated inbound tag.
# ============================================================

def _dx_routes_by_id():
    return {
        route["id"]: route
        for route in _direct_routes.list_routes(include_private=True)
    }


def _dx_inbound(cfg, tag):
    for inbound in cfg.get("inbounds", []):
        if inbound.get("tag") == tag:
            return inbound
    raise RuntimeError(f"Direct Xray inbound not found: {tag}")


def _dx_clients(cfg, tag):
    return (
        _dx_inbound(cfg, tag)
        .setdefault("settings", {})
        .setdefault("clients", [])
    )


def _dx_client_by_email(clients, email):
    target = str(email or "").lower()
    for client in clients:
        if str(client.get("email") or "").lower() == target:
            return client
    return None


def _dx_main_client(cfg, name):
    client = _dx_client_by_email(_clients(cfg), name)
    if client is None:
        raise ValueError("User not found")
    return client


def _dx_runtime_add(client, source_cfg, tag):
    inbound = copy.deepcopy(_dx_inbound(source_cfg, tag))
    inbound.setdefault("settings", {})["clients"] = [copy.deepcopy(client)]
    path = _write_temp_json({"inbounds": [inbound]})
    try:
        proc = _run([
            XRAY, "api", "adu",
            "--server=" + API,
            path,
        ])
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0 or "Added 1 user(s)" not in output:
            raise RuntimeError(
                output.strip() or f"Runtime add failed for direct inbound {tag}"
            )
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _dx_runtime_remove(email, tag):
    proc = _run([
        XRAY, "api", "rmu",
        "--server=" + API,
        "-tag=" + tag,
        email,
    ])
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0 or "Removed 1 user(s)" not in output:
        raise RuntimeError(
            output.strip() or f"Runtime remove failed for direct inbound {tag}"
        )


def _dx_rollback_runtime(executed, source_cfg):
    errors = []
    for action, tag, client in reversed(executed):
        email = client.get("email") or ""
        try:
            if action == "add":
                _dx_runtime_remove(email, tag)
            else:
                _dx_runtime_add(client, source_cfg, tag)
        except Exception as exc:
            errors.append(f"{action}:{tag}:{email}: {exc}")
    return errors


def _dx_execute_runtime(actions, source_cfg):
    executed = []
    try:
        for action, tag, client in actions:
            if action == "add":
                _dx_runtime_add(client, source_cfg, tag)
            elif action == "remove":
                _dx_runtime_remove(client.get("email") or "", tag)
            else:
                raise RuntimeError(f"Unknown direct runtime action: {action}")
            executed.append((action, tag, copy.deepcopy(client)))
    except Exception as exc:
        rollback_errors = _dx_rollback_runtime(executed, source_cfg)
        if rollback_errors:
            raise RuntimeError(
                "Direct runtime mutation failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise
    return executed


def _dx_restore_config_and_runtime(old_cfg, executed):
    errors = _dx_rollback_runtime(executed, old_cfg)
    try:
        _persist(old_cfg)
    except Exception as exc:
        errors.append("config: " + str(exc))
    return errors


def _dx_reconcile_user_routes(name, assigned_route_ids, write_state=True):
    assigned_route_ids = list(dict.fromkeys(
        str(value).strip().lower()
        for value in (assigned_route_ids or [])
        if str(value).strip()
    ))
    definitions = _dx_routes_by_id()
    unknown = [route_id for route_id in assigned_route_ids if route_id not in definitions]
    if unknown:
        raise ValueError("Unknown direct route: " + ", ".join(unknown))

    enabled = {
        route["id"]
        for route in _direct_routes.enabled_routes(include_private=True)
    }
    desired_active = set(assigned_route_ids) & enabled

    with LOCK:
        cfg = _load()
        main_client = copy.deepcopy(_dx_main_client(cfg, name))
        actual = main_client.get("email") or _validate_name(name)
        old_assignment = _direct_routes.assigned_route_ids(actual)
        new_cfg = copy.deepcopy(cfg)
        actions = []

        for route_id, route in definitions.items():
            tag = route["inbound_tag"]
            desired = route_id in desired_active
            try:
                current_clients = _dx_clients(cfg, tag)
                new_clients = _dx_clients(new_cfg, tag)
            except RuntimeError:
                if desired:
                    raise RuntimeError(
                        f"Direct route {route_id} is enabled but Xray inbound {tag} is missing"
                    )
                continue

            current = _dx_client_by_email(current_clients, actual)
            new_clients[:] = [
                client
                for client in new_clients
                if str(client.get("email") or "").lower() != actual.lower()
            ]

            if desired:
                new_clients.append(copy.deepcopy(main_client))

            if current is None and desired:
                actions.append(("add", tag, copy.deepcopy(main_client)))
            elif current is not None and not desired:
                actions.append(("remove", tag, copy.deepcopy(current)))
            elif current is not None and desired:
                if str(current.get("id") or "") != str(main_client.get("id") or ""):
                    actions.append(("remove", tag, copy.deepcopy(current)))
                    actions.append(("add", tag, copy.deepcopy(main_client)))

        _validate_config(new_cfg)
        executed = _dx_execute_runtime(actions, cfg)
        persisted = False
        try:
            _persist(new_cfg)
            persisted = True
            if write_state:
                _direct_routes.set_user_routes(actual, assigned_route_ids)
        except Exception as exc:
            rollback_errors = _dx_rollback_runtime(executed, cfg)
            if persisted:
                try:
                    _persist(cfg)
                except Exception as rollback_exc:
                    rollback_errors.append("config: " + str(rollback_exc))
            if write_state:
                try:
                    _direct_routes.set_user_routes(actual, old_assignment)
                except Exception as rollback_exc:
                    rollback_errors.append("route-state: " + str(rollback_exc))
            if rollback_errors:
                raise RuntimeError(
                    "Direct route update failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from exc
            raise

    return {
        "success": True,
        "name": actual,
        "route_ids": assigned_route_ids,
        "active_route_ids": [
            route_id for route_id in assigned_route_ids if route_id in enabled
        ],
        "enforced": True,
    }


def set_direct_routes(name, route_ids):
    return _dx_reconcile_user_routes(name, route_ids, write_state=True)


def _dx_sync_global_route(route_id, enabled):
    route_id = str(route_id or "").strip().lower()
    definitions = _dx_routes_by_id()
    route = definitions.get(route_id)
    if route is None:
        raise ValueError("Unknown direct route")

    old_route = next(
        (item for item in _direct_routes.list_routes() if item["id"] == route_id),
        None,
    )
    old_enabled = bool(old_route and old_route.get("enabled"))
    tag = route["inbound_tag"]

    with LOCK:
        cfg = _load()
        main_clients = {
            str(client.get("email") or "").lower(): copy.deepcopy(client)
            for client in _clients(cfg)
            if client.get("email")
        }

        try:
            current_clients = _dx_clients(cfg, tag)
        except RuntimeError:
            if enabled:
                raise RuntimeError(
                    f"Cannot enable {route_id}: Xray inbound {tag} is missing"
                )
            _direct_routes.set_route_enabled(route_id, False)
            return {
                "success": True,
                "route_id": route_id,
                "enabled": False,
                "enforced": True,
            }

        desired_emails = set()
        if enabled:
            for email in main_clients:
                if route_id in _direct_routes.assigned_route_ids(email):
                    desired_emails.add(email)

        new_cfg = copy.deepcopy(cfg)
        new_clients = _dx_clients(new_cfg, tag)
        unmanaged = [
            copy.deepcopy(client)
            for client in current_clients
            if str(client.get("email") or "").lower() not in main_clients
        ]
        desired_clients = [
            copy.deepcopy(main_clients[email])
            for email in sorted(desired_emails)
        ]
        new_clients[:] = unmanaged + desired_clients

        actions = []
        current_managed = {
            str(client.get("email") or "").lower(): copy.deepcopy(client)
            for client in current_clients
            if str(client.get("email") or "").lower() in main_clients
        }
        for email, current in current_managed.items():
            desired = main_clients.get(email) if email in desired_emails else None
            if desired is None:
                actions.append(("remove", tag, current))
            elif str(current.get("id") or "") != str(desired.get("id") or ""):
                actions.append(("remove", tag, current))
                actions.append(("add", tag, desired))

        for email in sorted(desired_emails):
            if email not in current_managed:
                actions.append(("add", tag, main_clients[email]))

        _validate_config(new_cfg)
        executed = _dx_execute_runtime(actions, cfg)
        persisted = False
        try:
            _persist(new_cfg)
            persisted = True
            _direct_routes.set_route_enabled(route_id, enabled)
        except Exception as exc:
            rollback_errors = _dx_rollback_runtime(executed, cfg)
            if persisted:
                try:
                    _persist(cfg)
                except Exception as rollback_exc:
                    rollback_errors.append("config: " + str(rollback_exc))
            try:
                _direct_routes.set_route_enabled(route_id, old_enabled)
            except Exception as rollback_exc:
                rollback_errors.append("route-state: " + str(rollback_exc))
            if rollback_errors:
                raise RuntimeError(
                    "Direct global route update failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from exc
            raise

    return {
        "success": True,
        "route_id": route_id,
        "enabled": bool(enabled),
        "enforced": True,
        "managed_members": len(desired_emails),
    }


def set_direct_route_enabled(route_id, enabled):
    return _dx_sync_global_route(route_id, bool(enabled))


def _dx_verify_user_memberships(name, routes):
    cfg = _load()
    main_client = _dx_main_client(cfg, name)
    actual = main_client.get("email") or _validate_name(name)
    expected_uuid = str(main_client.get("id") or "")
    for route in routes:
        tag = route["inbound_tag"]
        client = _dx_client_by_email(_dx_clients(cfg, tag), actual)
        if client is None:
            raise RuntimeError(
                f"Direct route {route['id']} is assigned but not active in Xray"
            )
        if str(client.get("id") or "") != expected_uuid:
            raise RuntimeError(
                f"Direct route {route['id']} has stale user credentials"
            )


_dx_base_direct_config_payload = direct_config_payload


def direct_config_payload(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    meta = _v30_registry_item(actual)
    bound_device_id = str(meta.get("bound_device_id") or "")
    if not bound_device_id:
        raise RuntimeError(
            "Activate the one-time EA enrollment on the target device before downloading Direct routes"
        )
    routes = _direct_routes.routes_for_user(actual)
    if not routes:
        raise RuntimeError("No enabled direct routes are assigned to this user")
    _dx_verify_user_memberships(actual, routes)
    return _dx_base_direct_config_payload(actual)


def _dx_refresh_user_uuid(name):
    with LOCK:
        cfg = _load()
        main_client = copy.deepcopy(_dx_main_client(cfg, name))
        actual = main_client.get("email") or _validate_name(name)
        new_cfg = copy.deepcopy(cfg)
        actions = []

        for route in _dx_routes_by_id().values():
            tag = route["inbound_tag"]
            try:
                current = _dx_client_by_email(_dx_clients(cfg, tag), actual)
                new_clients = _dx_clients(new_cfg, tag)
            except RuntimeError:
                continue
            if current is None:
                continue
            if str(current.get("id") or "") == str(main_client.get("id") or ""):
                continue
            new_clients[:] = [
                client for client in new_clients
                if str(client.get("email") or "").lower() != actual.lower()
            ]
            new_clients.append(copy.deepcopy(main_client))
            actions.append(("remove", tag, copy.deepcopy(current)))
            actions.append(("add", tag, copy.deepcopy(main_client)))

        if not actions:
            return {"success": True, "updated_routes": 0}

        _validate_config(new_cfg)
        executed = _dx_execute_runtime(actions, cfg)
        persisted = False
        try:
            _persist(new_cfg)
            persisted = True
        except Exception as exc:
            rollback_errors = _dx_rollback_runtime(executed, cfg)
            if persisted:
                try:
                    _persist(cfg)
                except Exception as rollback_exc:
                    rollback_errors.append("config: " + str(rollback_exc))
            if rollback_errors:
                raise RuntimeError(
                    "Direct credential sync failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from exc
            raise

    return {"success": True, "updated_routes": len(actions) // 2}


_dx_base_replace_vless_uuid = _v31_replace_vless_uuid


def _v31_replace_vless_uuid(name, replacement_uuid, snapshot_usage=True):
    old_uuid, new_uuid = _dx_base_replace_vless_uuid(
        name,
        replacement_uuid,
        snapshot_usage=snapshot_usage,
    )
    try:
        _dx_refresh_user_uuid(name)
    except Exception as exc:
        rollback_errors = []
        try:
            _dx_base_replace_vless_uuid(
                name,
                old_uuid,
                snapshot_usage=False,
            )
        except Exception as rollback_exc:
            rollback_errors.append("main-credential: " + str(rollback_exc))
        if rollback_errors:
            raise RuntimeError(
                "Direct credential sync failed and main credential rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise
    return old_uuid, new_uuid


_dx_base_delete_user = _direct_routes_base_delete_user


def delete_user(name):
    if not _dx_routes_by_id():
        return _dx_base_delete_user(name)

    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    old_assignment = _direct_routes.assigned_route_ids(actual)

    _dx_reconcile_user_routes(actual, [], write_state=True)
    try:
        result = _dx_base_delete_user(actual)
    except Exception as exc:
        rollback_errors = []
        try:
            _dx_reconcile_user_routes(actual, old_assignment, write_state=True)
        except Exception as rollback_exc:
            rollback_errors.append("direct-membership: " + str(rollback_exc))
        if rollback_errors:
            raise RuntimeError(
                "User deletion failed and Direct membership rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise

    try:
        _direct_routes.drop_user(actual)
    except Exception as exc:
        result["direct_route_warning"] = str(exc)[:300]
    return result

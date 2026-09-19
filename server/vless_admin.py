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
        _v30_lock_inner_uri(p, lock_hash, expiration_ms)
        + "\n"
        + _v30_lock_inner_uri(b, lock_hash, expiration_ms)
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
    _, client = _get_client(name)
    actual = client.get("email") or name
    if not delivery_password or len(delivery_password) < 6:
        raise ValueError("Delivery password must be at least 6 characters")
    meta = _v30_registry_item(actual)
    lock_hash = meta.get("profile_lock_hash")
    if not lock_hash:
        lock_hash = _v30_password_hash(_align_secrets.token_urlsafe(32))
    expires_at = int(meta.get("expires_at", 0) or 0)
    encrypted, artifact = _v30_write_encrypted_artifact(
        actual,
        delivery_password,
        lock_hash,
        expires_at * 1000 if expires_at else 0,
    )
    _v30_registry_update(actual, {
        "delivery_password_hash": _v30_password_hash(delivery_password),
        "profile_lock_hash": lock_hash,
        "artifact": artifact.name,
        "managed_profile": True,
    })
    return {"success": True, "name": actual, "filename": artifact.name}


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

    # Keep client-visible expiry in the encrypted artifact. Rotating limits does
    # not decrypt/re-encrypt because the server intentionally does not retain
    # the customer's delivery password. The runtime/server expiry remains
    # authoritative; use rotate_delivery_password() when issuing a new artifact.
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
# SLIPNET_EA_ONE_TIME_ENROLLMENT_V1
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


def _v31_enrollment_uri(name, token):
    urls = _v31_enrollment_urls(name)
    body = {
        "v": 1,
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
    uri = _v31_enrollment_uri(actual, token)
    artifact = _v31_write_enrollment_artifact(actual, uri)
    _v30_registry_update(actual, {
        "artifact": artifact.name,
        "managed_profile": True,
        "delivery_password_hash": "",
        "enrollment_state": "unused",
        "enrollment_token_hash": _v31_token_hash(token),
        "enrollment_created_at": now,
        "enrollment_expires_at": now + _V31_ENROLLMENT_TTL_SECONDS,
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
        "version": 1,
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
        state = str(item.get("enrollment_state") or "")

        if state == "unused":
            item["enrollment_state"] = "pending"
            item["bound_device_id"] = device_id
            item["bound_device_key_sha256"] = key_sha256
        elif state == "pending":
            _v31_require_same_device(item, device_id, key_sha256)
        elif state == "redeemed":
            raise EnrollmentAlreadyUsedError(
                "This one-time configuration has already been used"
            )
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


def redeem_enrollment(token, device_id, public_key_b64, challenge, signature_b64):
    token, device_id, key_sha256, public_key = _v31_decode_device_identity(
        token, device_id, public_key_b64
    )
    challenge = str(challenge or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", challenge):
        raise ValueError("Invalid enrollment challenge")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        raise ValueError("Invalid device signature")

    digest = _v31_token_hash(token)
    now = int(time.time())
    actual = None
    lock_hash = None
    expires_at = 0

    with _ALIGN_REGISTRY_LOCK:
        reg = _align_registry()
        actual, item = _v31_find_enrollment(reg, digest)
        _v31_validate_enrollment_window(item, now)
        state = str(item.get("enrollment_state") or "")
        if state not in ("pending", "redeemed"):
            raise PermissionError("Enrollment challenge is required")

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
            "slipnet-enroll-challenge-v1\n"
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

        item["enrollment_state"] = "redeemed"
        if not int(item.get("enrollment_redeemed_at", 0) or 0):
            item["enrollment_redeemed_at"] = now
        # Keep only the last signed challenge until its short TTL expires so
        # the exact same redeem POST can be replayed after a lost response.
        # No new challenge can be issued once state is redeemed.
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
        "enrollment_state": "redeemed",
    }


def _v31_rotate_vless_uuid(name):
    # Snapshot current raw counters into durable totals before Xray runtime
    # removes/re-adds the email and potentially resets raw per-user counters.
    _v31_base_list_users()

    meta = _v30_registry_item(name)
    if str(meta.get("access_state") or "active") != "active":
        raise RuntimeError("Reset Device requires an active subscription")

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

        new_client = copy.deepcopy(old_client)
        new_client["id"] = str(uuidlib.uuid4())
        new_cfg = copy.deepcopy(cfg)
        _clients(new_cfg)[index] = copy.deepcopy(new_client)
        _validate_config(new_cfg)

        _runtime_remove(old_client.get("email") or name)
        new_runtime_added = False
        try:
            _runtime_add(new_client, cfg)
            new_runtime_added = True
            _persist(new_cfg)
        except Exception:
            if new_runtime_added:
                try:
                    _runtime_remove(new_client.get("email") or name)
                except Exception:
                    pass
            # Restore exactly once. Failure to restore is intentionally not
            # hidden behind a second add attempt.
            try:
                _runtime_add(old_client, cfg)
            except Exception:
                pass
            raise

    return new_client["id"]


def reissue_enrollment(name):
    _, client = _get_client(name)
    actual = client.get("email") or _validate_name(name)
    meta = _v30_registry_item(actual)

    # Legacy users may predate the managed-profile registry entirely. Prepare
    # the lock metadata without touching their working VLESS credential. If
    # credential rotation later fails, the old credential remains usable.
    if not meta.get("profile_lock_hash"):
        _v30_registry_update(actual, {
            "managed_profile": True,
            "profile_lock_hash": _v30_password_hash(_align_secrets.token_urlsafe(32)),
            "created_at": int(meta.get("created_at", 0) or int(time.time())),
            "expires_at": int(meta.get("expires_at", 0) or 0),
            "quota_bytes": int(meta.get("quota_bytes", 0) or 0),
            "access_state": str(meta.get("access_state") or "active"),
        })

    _v31_rotate_vless_uuid(actual)
    result = _v31_issue_enrollment(actual)
    result["credential_rotated"] = True
    return result


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
    if state == "redeemed":
        raise RuntimeError("Enrollment already activated; use Reset Device to issue a new one-time file")
    if state != "unused":
        raise RuntimeError("Enrollment is not available")

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
        "version": 1,
        "one_time_enrollment": True,
        "enrollment_state": "unused",
        "enrollment_expires_at": int(meta.get("enrollment_expires_at", 0) or 0),
    }


def config_uri(name):
    return config_payload(name)["uri"]


def profile_artifact(name):
    payload = config_payload(name)
    return _v30_artifact_path(payload["name"]), payload

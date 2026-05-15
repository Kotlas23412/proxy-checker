#!/usr/bin/env python3
import json
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

INPUT_FILE = Path("filtered_vless.txt")
WORKING_FILE = Path("working_vless.txt")
BUNDLE_FILE = Path("working_bundle.txt")
CHECK_URL = "http://www.gstatic.com/generate_204"
INTERVAL_SECONDS = 3600
XRAY_BIN = "xray"


def parse_vless_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("vless://")
    ]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def link_to_outbound(link: str) -> dict:
    p = urllib.parse.urlsplit(link)
    q = urllib.parse.parse_qs(p.query)
    uid = urllib.parse.unquote(p.username or "")
    host = p.hostname
    port = p.port or 443

    if not uid or not host:
        raise ValueError("invalid vless link")

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uid, "encryption": "none"}]
            }]
        },
        "streamSettings": {
            "network": q.get("type", ["tcp"])[0],
            "security": q.get("security", ["none"])[0],
        }
    }

    user = outbound["settings"]["vnext"][0]["users"][0]
    if "flow" in q:
        user["flow"] = q["flow"][0]

    stream = outbound["streamSettings"]
    if "sni" in q:
        stream.setdefault("tlsSettings", {})["serverName"] = q["sni"][0]
    if "alpn" in q:
        stream.setdefault("tlsSettings", {})["alpn"] = q["alpn"][0].split(",")

    if stream["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": q.get("sni", [host])[0],
            "fingerprint": q.get("fp", ["chrome"])[0],
            "publicKey": q.get("pbk", [""])[0],
            "shortId": q.get("sid", [""])[0],
        }

    return outbound


def check_link_via_xray(link: str, timeout: int = 15) -> bool:
    socks_port = free_port()
    outbound = link_to_outbound(link)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound],
    }

    tmp = Path(f"/tmp/xray_check_{socks_port}.json")
    tmp.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

    proc = subprocess.Popen([XRAY_BIN, "run", "-c", str(tmp)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        proxy = urllib.request.ProxyHandler({"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"})
        opener = urllib.request.build_opener(proxy)
        req = urllib.request.Request(CHECK_URL, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=timeout) as r:
            return r.status in (200, 204)
    except Exception:
        return False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
        tmp.unlink(missing_ok=True)


def run_once() -> None:
    links = parse_vless_lines(INPUT_FILE)
    working: list[str] = []
    for i, link in enumerate(links, start=1):
        ok = False
        try:
            ok = check_link_via_xray(link)
        except Exception:
            ok = False
        print(f"[{i}/{len(links)}] {'OK' if ok else 'DEAD'}")
        if ok:
            working.append(link)

    WORKING_FILE.write_text("\n".join(working) + ("\n" if working else ""), encoding="utf-8")
    lines = [
        f"# updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"# total_working: {len(working)}",
        "",
        *working,
    ]
    BUNDLE_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Saved working: {len(working)}")


def main() -> None:
    print("Hourly checker started. Press Ctrl+C to stop.")
    while True:
        started = time.time()
        run_once()
        sleep_for = max(0, INTERVAL_SECONDS - (time.time() - started))
        print(f"Sleep {int(sleep_for)} sec")
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()

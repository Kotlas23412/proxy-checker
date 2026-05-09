#!/usr/bin/env python3
import json
import os
import shlex
import logging
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

FILTERED_FILE = Path("filtered_vless.txt")
WORKING_FILE = Path("working_vless.txt")

XRAY_CMD = os.environ.get("XRAY_CMD", "xray")


def build_xray_command(config_path: str) -> list[str]:
    base_cmd = shlex.split(XRAY_CMD)
    return base_cmd + ["run", "-config", config_path]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def log_step(message: str) -> None:
    logging.info(message)


def parse_vless_for_xray(link: str) -> dict:
    parsed = urllib.parse.urlsplit(link)
    if parsed.scheme != "vless" or not parsed.hostname or not parsed.username:
        raise ValueError("Некорректная VLESS ссылка")

    query = urllib.parse.parse_qs(parsed.query)

    def get(key: str, default: str = "") -> str:
        return query.get(key, [default])[0] or default

    security = get("security", "none")
    network = get("type", "tcp")

    user = {"id": parsed.username, "encryption": "none"}
    flow = get("flow")
    if flow:
        user["flow"] = flow

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port or 443,
                "users": [user],
            }]
        },
        "streamSettings": {"network": network},
    }

    stream = outbound["streamSettings"]
    if security in {"tls", "reality"}:
        stream["security"] = security
        tls_obj = {}
        sni = get("sni") or get("serverName")
        if sni:
            tls_obj["serverName"] = sni
        fp = get("fp")
        if fp:
            tls_obj["fingerprint"] = fp
        if security == "tls":
            stream["tlsSettings"] = tls_obj
        else:
            tls_obj["publicKey"] = get("pbk")
            tls_obj["shortId"] = get("sid")
            tls_obj["spiderX"] = get("spx", "/")
            stream["realitySettings"] = tls_obj

    if network == "ws":
        stream["wsSettings"] = {
            "path": get("path", "/"),
            "headers": {"Host": get("host") or parsed.hostname},
        }
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": get("serviceName") or get("path")}

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "port": 2080,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
        "routing": {
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]
        },
    }


def check_vless_with_xray(link: str, timeout: int = 12) -> bool:
    try:
        config = parse_vless_for_xray(link)
    except Exception:
        return False

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as cfg:
        json.dump(config, cfg, ensure_ascii=False)
        cfg_path = cfg.name

    proc = None
    try:
        proc = subprocess.Popen(build_xray_command(cfg_path), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)

        req = urllib.request.Request("http://cp.cloudflare.com/generate_204", headers={"User-Agent": "Mozilla/5.0"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": "socks5h://127.0.0.1:2080", "https": "socks5h://127.0.0.1:2080"})
        )
        with opener.open(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        Path(cfg_path).unlink(missing_ok=True)


def main() -> None:
    if not FILTERED_FILE.exists():
        log_step(f"Файл не найден: {FILTERED_FILE}")
        return

    if XRAY_CMD == "xray" and not shutil.which("xray"):
        raise RuntimeError("xray не найден в PATH")

    links = [line.strip() for line in FILTERED_FILE.read_text(encoding="utf-8").splitlines() if line.strip().startswith("vless://")]
    log_step(f"Старт Xray проверки: {len(links)} ссылок")

    working = []
    for idx, link in enumerate(links, 1):
        if check_vless_with_xray(link):
            working.append(link)
        if idx % 50 == 0 or idx == len(links):
            log_step(f"Xray прогресс: {idx}/{len(links)} | рабочих: {len(working)}")

    WORKING_FILE.write_text("\n".join(working) + ("\n" if working else ""), encoding="utf-8")
    log_step(f"Рабочие прокси сохранены: {WORKING_FILE} | всего: {len(working)}")


if __name__ == "__main__":
    main()

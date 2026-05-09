#!/usr/bin/env python3
import json
import logging
import shutil
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path
import concurrent.futures
import threading

FILTERED_FILE = Path("filtered_vless.txt")
WORKING_FILE = Path("working_vless.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

port_lock = threading.Lock()
current_port = 20000
checked_count = 0
working_count = 0
total_links = 0
count_lock = threading.Lock()

def log_step(message: str) -> None:
    logging.info(message)

def get_next_port() -> int:
    global current_port
    with port_lock:
        current_port += 1
        return current_port

def parse_vless_for_xray(link: str, local_port: int) -> dict:
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
                "port": int(parsed.port or 443),
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
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks-in",
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
        "routing": {
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]
        },
    }

def check_vless_with_xray(link: str, timeout: int = 7) -> bool:
    local_port = get_next_port()
    try:
        config = parse_vless_for_xray(link, local_port)
    except Exception:
        return False

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as cfg:
        json.dump(config, cfg, ensure_ascii=False)
        cfg_path = cfg.name

    proc = None
    try:
        proc = subprocess.Popen(["xray", "run", "-config", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5) # Даем Xray полсекунды на запуск

        if proc.poll() is not None:
            return False # Xray упал из-за кривого конфига

        # Используем системный cURL для проверки SOCKS5 (с резолвом DNS через прокси)
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--socks5-hostname", f"127.0.0.1:{local_port}",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout),
            "http://cp.cloudflare.com/generate_204"
        ]
        
        result = subprocess.run(curl_cmd, capture_output=True, text=True)
        return result.stdout.strip() in ("200", "204")
        
    except Exception:
        return False
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
        Path(cfg_path).unlink(missing_ok=True)

def process_link(link: str):
    global checked_count, working_count
    
    is_working = check_vless_with_xray(link)
    
    with count_lock:
        checked_count += 1
        if is_working:
            working_count += 1
        
        if checked_count % 100 == 0 or checked_count == total_links:
            log_step(f"Прогресс: {checked_count}/{total_links} | Рабочих: {working_count}")
            
    return link if is_working else None

def main() -> None:
    global total_links
    
    if not FILTERED_FILE.exists():
        log_step(f"Файл не найден: {FILTERED_FILE}")
        return

    if not shutil.which("xray"):
        raise RuntimeError("xray не найден в PATH")

    links = list(set([line.strip() for line in FILTERED_FILE.read_text(encoding="utf-8").splitlines() if line.strip().startswith("vless://")]))
    total_links = len(links)
    log_step(f"Старт многопоточной проверки: {total_links} уникальных ссылок")

    working = []
    
    # 20 потоков оптимально для бесплатного раннера GitHub
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(process_link, link) for link in links]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                working.append(result)

    WORKING_FILE.write_text("\n".join(working) + ("\n" if working else ""), encoding="utf-8")
    log_step(f"Рабочие прокси сохранены: {WORKING_FILE} | Всего: {len(working)}")

if __name__ == "__main__":
    main()

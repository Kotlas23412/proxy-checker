#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль управления xray: конфигурация, запуск, остановка, загрузка.
"""

import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
import zipfile

import requests
from rich.console import Console

from . import config
from .config import (
    XRAY_DIR_NAME,
    XRAY_RELEASES_API,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
)

console = Console()


def build_xray_config(parsed: dict, socks_port: int) -> dict:
    """
    Собирает конфиг xray: inbound SOCKS, outbound для различных протоколов.
    Поддерживает: VLESS, VMess, Trojan, Shadowsocks.
    """
    protocol = parsed.get("protocol", "vless")
    address = parsed.get("address", "")
    port = parsed.get("port", 443)
    
    # Базовые stream settings
    network = parsed.get("network", "tcp")
    security = parsed.get("security", "none")
    
    # Для VMess security может быть в поле "tls"
    if protocol == "vmess" and parsed.get("tls"):
        security = parsed.get("tls", "none")
    
    stream = {
        "network": network,
        "security": security,
    }
    
    # Настройки для разных типов безопасности
    if security == "reality":
        stream["realitySettings"] = {
            "fingerprint": parsed.get("fingerprint") or "chrome",
            "serverName": parsed.get("serverName") or "",
            "publicKey": parsed.get("publicKey") or "",
            "shortId": parsed.get("shortId") or "",
        }
    elif security == "tls":
        stream["tlsSettings"] = {
            "serverName": parsed.get("serverName") or "",
            "allowInsecure": False,
        }
    
    # Настройки для разных типов сетей
    if network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": parsed.get("grpcServiceName") or ""
        }
    elif network == "ws":
        stream["wsSettings"] = {
            "path": parsed.get("wsPath") or "/",
            "headers": {}
        }
        if parsed.get("wsHost"):
            stream["wsSettings"]["headers"]["Host"] = parsed["wsHost"]
    elif network == "xhttp":
        stream["xhttpSettings"] = {"mode": parsed.get("mode") or "auto"}
    elif network == "h2":
        stream["httpSettings"] = {
            "path": parsed.get("wsPath") or "/",
            "host": [parsed.get("wsHost")] if parsed.get("wsHost") else []
        }
    
    # Строим outbound в зависимости от протокола
    outbound = {
        "protocol": protocol,
        "streamSettings": stream,
        "tag": "proxy",
    }
    
    if protocol == "vless":
        user = {"id": parsed.get("uuid", ""), "encryption": "none"}
        if parsed.get("flow"):
            user["flow"] = parsed["flow"]
        outbound["settings"] = {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user],
                }
            ]
        }
    elif protocol == "vmess":
        user = {
            "id": parsed.get("id", ""),
            "alterId": parsed.get("alterId", 0),
            "security": parsed.get("security", "auto"),
        }
        outbound["settings"] = {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user],
                }
            ]
        }
    elif protocol == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "password": parsed.get("password", ""),
                }
            ]
        }
    elif protocol == "shadowsocks":
        outbound["settings"] = {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "method": parsed.get("method", "aes-256-gcm"),
                    "password": parsed.get("password", ""),
                }
            ]
        }
    else:
        raise ValueError(f"Неподдерживаемый протокол: {protocol}")
    
    # ВАЖНО: Убираем system-proxy! Теперь весь трафик идёт через Exit Node
    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
                "tag": "in",
            }
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"}
            ],
        },
    }


def reload_xray_config(proc: subprocess.Popen) -> bool:
    """
    Просит Xray перечитать конфиг с диска (тот же путь -c).
    На Linux/macOS: SIGHUP. На Windows не поддерживается (False).
    """
    if proc is None or proc.poll() is not None:
        return False
    if sys.platform == "win32":
        return False
    try:
        os.kill(proc.pid, signal.SIGHUP)
        time.sleep(0.08)
        return proc.poll() is None
    except (OSError, ProcessLookupError, ValueError):
        return False


def run_xray(config_path: str, stderr_pipe: bool = False):
    """Запуск xray. При stderr_pipe=True stderr возвращается в proc.stderr."""
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE if stderr_pipe else subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        [config.XRAY_CMD, "run", "-config", config_path],
        **kwargs,
    )


def kill_xray_process(proc: subprocess.Popen, drain_stderr: bool = True) -> None:
    """Гарантированно завершает процесс xray."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if drain_stderr and getattr(proc, "stderr", None):
            try:
                proc.stderr.close()
            except (OSError, ValueError):
                pass
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=2)
        return
    except (subprocess.TimeoutExpired, OSError, ProcessLookupError):
        pass
    try:
        if sys.platform != "win32":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
        proc.wait(timeout=1)
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        pass


def check_xray_available() -> bool:
    """Проверяет доступность xray."""
    try:
        p = subprocess.run(
            [config.XRAY_CMD, "version"],
            capture_output=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return p.returncode == 0
    except (FileNotFoundError, Exception):
        return False


def _get_xray_platform_asset_name() -> str | None:
    """Определяет имя asset для текущей платформы."""
    machine = (platform.machine() or "").lower()
    system = (platform.system() or "").lower()
    is_64 = "64" in machine or machine in ("amd64", "x86_64", "aarch64", "arm64")
    is_arm = "arm" in machine or "aarch" in machine
    
    if system == "windows":
        if is_arm:
            return "Xray-windows-arm64-v8a.zip"
        return "Xray-windows-64.zip" if is_64 else "Xray-windows-32.zip"
    if system == "linux":
        if is_arm:
            return "Xray-linux-arm64-v8a.zip" if "64" in machine else "Xray-linux-arm32-v7a.zip"
        return "Xray-linux-64.zip" if is_64 else "Xray-linux-32.zip"
    if system == "darwin":
        return "Xray-macos-arm64-v8a.zip" if is_arm else "Xray-macos-64.zip"
    return None


def _download_xray_to(dir_path: str) -> str | None:
    """Скачивает Xray-core с GitHub."""
    asset_name = _get_xray_platform_asset_name()
    if not asset_name:
        console.print(f"[yellow]Неподдерживаемая платформа:[/yellow] {platform.system()}/{platform.machine()}")
        return None
    
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    zip_path = os.path.join(dir_path, "xray.zip")
    
    for attempt in range(1, 4):  # 3 попытки
        try:
            if attempt > 1:
                console.print(f"[yellow]Повтор загрузки ({attempt}/3)...[/yellow]")
                time.sleep(10)
            
            # Получаем latest release
            r = requests.get(XRAY_RELEASES_API, timeout=15)
            r.raise_for_status()
            data = r.json()
            
            # Ищем нужный asset
            download_url = None
            for a in data.get("assets", []):
                if a.get("name") == asset_name:
                    download_url = a.get("browser_download_url")
                    break
            
            if not download_url:
                console.print(f"[red]Asset не найден:[/red] {asset_name}")
                return None
            
            tag = data.get("tag_name", "unknown")
            console.print(f"[cyan]Загрузка Xray {tag}...[/cyan]")
            
            # Скачиваем
            with requests.get(download_url, stream=True, timeout=90) as resp:
                resp.raise_for_status()
                with open(zip_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)
            
            # Распаковываем
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(dir_path)
            
            os.remove(zip_path)
            
            # Ищем исполняемый файл
            for root, _, files in os.walk(dir_path):
                for f in files:
                    if f.lower() == exe_name:
                        path = os.path.join(root, f)
                        os.chmod(path, 0o755)
                        console.print(f"[green]Xray установлен:[/green] {path}")
                        return os.path.abspath(path)
            
            console.print("[red]Исполняемый файл не найден в архиве[/red]")
            return None
            
        except Exception as e:
            if os.path.isfile(zip_path):
                try:
                    os.remove(zip_path)
                except OSError:
                    pass
            if attempt == 3:
                console.print(f"[red]Ошибка загрузки:[/red] {e}")
                return None
    
    return None


def ensure_xray() -> bool:
    """Проверяет наличие xray и при необходимости скачивает."""
    # 1. Проверяем XRAY_PATH из переменных окружения
    if os.environ.get("XRAY_PATH"):
        return check_xray_available()
    
    # 2. Проверяем PATH
    if check_xray_available():
        return True
    
    # 3. Проверяем tools/xray в репозитории
    from pathlib import Path
    script_dir = Path(__file__).resolve().parent
    if script_dir.name == "lib":
        script_dir = script_dir.parent
    
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    tools_xray = script_dir / "tools" / exe_name
    
    if tools_xray.is_file():
        config.XRAY_CMD = str(tools_xray)
        if check_xray_available():
            console.print(f"[green]Используется Xray из репо:[/green] {tools_xray}\n")
            return True
    
    # 4. Проверяем локальную директорию xray_dist
    xray_dir = script_dir / XRAY_DIR_NAME
    local_path = xray_dir / exe_name
    
    if local_path.is_file():
        config.XRAY_CMD = str(local_path)
        if check_xray_available():
            console.print(f"[green]Используется локальный Xray:[/green] {local_path}\n")
            return True
    
    # 5. Скачиваем
    os.makedirs(str(xray_dir), exist_ok=True)
    path = _download_xray_to(str(xray_dir))
    if path:
        config.XRAY_CMD = path
        return check_xray_available()
    
    return False

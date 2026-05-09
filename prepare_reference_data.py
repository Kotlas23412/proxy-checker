#!/usr/bin/env python3
import ipaddress
import json
import logging
import urllib.request
from pathlib import Path
from typing import Set

SNI_JSON_URL = "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/sni/out/domains.json"
IPS_JSON_URL = "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/sort/out/sorted.c.json"

DATA_DIR = Path("data")
SNI_DOMAINS_FILE = DATA_DIR / "sni_domains.txt"
IP_LIST_FILE = DATA_DIR / "ip_list.txt"
CIDR_LIST_FILE = DATA_DIR / "cidr_list.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def download_json(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_domains(data: object) -> Set[str]:
    domains: Set[str] = set()
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            sans = item.get("sans")
            if isinstance(sans, list):
                for domain in sans:
                    if isinstance(domain, str):
                        clean = domain.replace("*.", "").strip().lower()
                        if clean and not clean.startswith("."):
                            domains.add(clean)
            cn = item.get("cn")
            if isinstance(cn, str):
                clean = cn.replace("*.", "").strip().lower()
                if clean and not clean.startswith("."):
                    domains.add(clean)
    return domains


def extract_ips_and_cidrs(data: object) -> tuple[Set[str], Set[str]]:
    ips: Set[str] = set()
    cidrs: Set[str] = set()
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            raw_ips = item.get("ips")
            if not isinstance(raw_ips, list):
                continue
            for raw in raw_ips:
                if not isinstance(raw, str):
                    continue
                value = raw.strip()
                if not value:
                    continue
                try:
                    if "/" in value:
                        cidrs.add(str(ipaddress.ip_network(value, strict=False)))
                    else:
                        ips.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
    return ips, cidrs


def write_lines(path: Path, values: Set[str]) -> None:
    path.write_text("\n".join(sorted(values)) + ("\n" if values else ""), encoding="utf-8")


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    logging.info("Скачивание IPS JSON...")
    ips_json = json.loads(download_json(IPS_JSON_URL))
    ips, cidrs = extract_ips_and_cidrs(ips_json)
    write_lines(IP_LIST_FILE, ips)
    write_lines(CIDR_LIST_FILE, cidrs)
    logging.info("Сохранено IP: %s (%s)", IP_LIST_FILE, len(ips))
    logging.info("Сохранено CIDR: %s (%s)", CIDR_LIST_FILE, len(cidrs))

    logging.info("Скачивание SNI JSON...")
    sni_json = json.loads(download_json(SNI_JSON_URL))
    domains = extract_domains(sni_json)
    write_lines(SNI_DOMAINS_FILE, domains)
    logging.info("Сохранено доменов: %s (%s)", SNI_DOMAINS_FILE, len(domains))

    logging.info("Готово. Теперь запускайте filter_vless_by_ip.py")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, List, Set, Tuple

SOURCE_LIST_FILE = Path("vless_sources.txt")
OUTPUT_FILE = Path("filtered_vless.txt")
SNI_JSON_URL = "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/sni/out/domains.json"
IPS_JSON_URL = "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/sort/out/sorted.c.json"


def download_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_string_values(data) -> List[str]:
    values: List[str] = []
    if isinstance(data, dict):
        for value in data.values():
            values.extend(extract_string_values(value))
    elif isinstance(data, list):
        for item in data:
            values.extend(extract_string_values(item))
    elif isinstance(data, str):
        values.append(data.strip())
    return values


def parse_ip_rules() -> Tuple[Set[ipaddress._BaseAddress], List[ipaddress._BaseNetwork]]:
    content = download_text(IPS_JSON_URL)
    data = json.loads(content)
    ips: Set[ipaddress._BaseAddress] = set()
    cidrs: List[ipaddress._BaseNetwork] = []

    for raw in extract_string_values(data):
        if not raw:
            continue
        try:
            if "/" in raw:
                cidrs.append(ipaddress.ip_network(raw, strict=False))
            else:
                ips.add(ipaddress.ip_address(raw))
        except ValueError:
            continue

    return ips, cidrs


def load_domains() -> Set[str]:
    content = download_text(SNI_JSON_URL)
    data = json.loads(content)
    return {d.lower() for d in extract_string_values(data) if d and isinstance(d, str)}


def load_source_urls() -> List[str]:
    if not SOURCE_LIST_FILE.exists():
        raise FileNotFoundError(f"Не найден файл с источниками: {SOURCE_LIST_FILE}")

    urls: List[str] = []
    for line in SOURCE_LIST_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def parse_vless_links(text: str) -> List[str]:
    links: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("vless://"):
            links.append(line)
    return links


def host_from_vless(link: str) -> str:
    parsed = urllib.parse.urlsplit(link)
    return (parsed.hostname or "").strip().lower()


def resolve_host_ips(host: str) -> Set[ipaddress._BaseAddress]:
    result: Set[ipaddress._BaseAddress] = set()

    try:
        result.add(ipaddress.ip_address(host))
        return result
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip_raw = info[4][0]
            try:
                result.add(ipaddress.ip_address(ip_raw))
            except ValueError:
                continue
    except socket.gaierror:
        pass

    return result


def matches_ip_rules(host_ips: Iterable[ipaddress._BaseAddress], ip_set: Set[ipaddress._BaseAddress], cidrs: List[ipaddress._BaseNetwork]) -> bool:
    for ip in host_ips:
        if ip in ip_set:
            return True
        for net in cidrs:
            if ip.version == net.version and ip in net:
                return True
    return False


def main() -> None:
    source_urls = load_source_urls()
    exact_ips, cidr_rules = parse_ip_rules()
    sni_domains = load_domains()

    all_links: Set[str] = set()
    for url in source_urls:
        try:
            content = download_text(url)
            links = parse_vless_links(content)
            all_links.update(links)
            print(f"Источник: {url} | VLESS: {len(links)}")
        except Exception as e:
            print(f"Ошибка при загрузке {url}: {e}")

    filtered: List[str] = []
    for link in sorted(all_links):
        host = host_from_vless(link)
        if not host:
            continue

        if host in sni_domains:
            filtered.append(link)
            continue

        ips = resolve_host_ips(host)
        if ips and matches_ip_rules(ips, exact_ips, cidr_rules):
            filtered.append(link)

    OUTPUT_FILE.write_text("\n".join(filtered) + ("\n" if filtered else ""), encoding="utf-8")
    print(f"Всего VLESS: {len(all_links)}")
    print(f"Отфильтровано: {len(filtered)}")
    print(f"Результат сохранён: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

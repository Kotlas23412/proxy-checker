#!/usr/bin/env python3
import ipaddress
import json
import logging
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Set, Tuple, Dict, Optional

SOURCE_LIST_FILE = Path("vless_sources.txt")
OUTPUT_FILE = Path("filtered_vless.txt")
DEBUG_FILE = Path("filter_debug.log")
SNI_JSON_URL = "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/sni/out/domains.json"
IPS_JSON_URL = "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/sort/out/sorted.c.json"

# Настройки производительности
MAX_WORKERS = 20
DNS_TIMEOUT = 2
BATCH_SIZE = 1000
ENABLE_DEBUG = True  # Включить детальное логирование

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Дополнительный логгер для отладки
debug_logger = logging.getLogger('debug')
debug_logger.setLevel(logging.DEBUG)
if ENABLE_DEBUG:
    fh = logging.FileHandler(DEBUG_FILE, mode='w', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
    debug_logger.addHandler(fh)


def log_step(message: str) -> None:
    logging.info(message)


def log_debug(message: str) -> None:
    if ENABLE_DEBUG:
        debug_logger.debug(message)


def download_text(url: str) -> str:
    log_step(f"Скачивание: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = response.read().decode("utf-8", errors="ignore")
    log_step(f"Скачано байт: {len(payload)} из {url}")
    return payload


def parse_ip_rules() -> Tuple[Set[ipaddress._BaseAddress], List[ipaddress._BaseNetwork]]:
    """Парсит JSON со списком IP адресов"""
    content = download_text(IPS_JSON_URL)
    data = json.loads(content)
    ips: Set[ipaddress._BaseAddress] = set()
    cidrs: List[ipaddress._BaseNetwork] = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "ips" in item:
                for ip_str in item["ips"]:
                    try:
                        if "/" in ip_str:
                            cidrs.append(ipaddress.ip_network(ip_str, strict=False))
                        else:
                            ips.add(ipaddress.ip_address(ip_str))
                    except ValueError:
                        continue

    log_step(f"Извлечено уникальных IP: {len(ips)}, CIDR: {len(cidrs)}")
    return ips, cidrs


def load_domains() -> Set[str]:
    """Парсит JSON с доменами из поля 'sans'"""
    content = download_text(SNI_JSON_URL)
    data = json.loads(content)
    domains: Set[str] = set()

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                if "sans" in item and isinstance(item["sans"], list):
                    for domain in item["sans"]:
                        if domain and isinstance(domain, str):
                            clean_domain = domain.replace("*.", "").strip().lower()
                            if clean_domain and not clean_domain.startswith("."):
                                domains.add(clean_domain)
                
                if "cn" in item and isinstance(item["cn"], str):
                    clean_cn = item["cn"].replace("*.", "").strip().lower()
                    if clean_cn and not clean_cn.startswith("."):
                        domains.add(clean_cn)

    log_step(f"Извлечено уникальных доменов: {len(domains)}")
    return domains


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
    """Extract host from VLESS link with fallback for malformed URLs."""
    try:
        parsed = urllib.parse.urlsplit(link)
        return (parsed.hostname or "").strip().lower()
    except ValueError:
        try:
            if not link.startswith("vless://"):
                return ""
            
            rest = link[8:]
            
            if "@" not in rest:
                return ""
            
            _, host_part = rest.split("@", 1)
            host = host_part.split("?")[0].split("#")[0]
            
            if ":" in host:
                if host.startswith("["):
                    bracket_end = host.find("]")
                    if bracket_end != -1:
                        host = host[1:bracket_end]
                else:
                    host = host.rsplit(":", 1)[0]
            
            return host.strip().lower()
        except Exception:
            return ""
    except Exception:
        return ""


def is_private_ip(ip: ipaddress._BaseAddress) -> bool:
    """Проверяет, является ли IP приватным/локальным"""
    if isinstance(ip, ipaddress.IPv4Address):
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    elif isinstance(ip, ipaddress.IPv6Address):
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    return False


def resolve_host_ips(host: str, timeout: float = DNS_TIMEOUT) -> Set[ipaddress._BaseAddress]:
    result: Set[ipaddress._BaseAddress] = set()

    try:
        ip = ipaddress.ip_address(host)
        result.add(ip)
        return result
    except ValueError:
        pass

    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip_raw = info[4][0]
            try:
                result.add(ipaddress.ip_address(ip_raw))
            except ValueError:
                continue
    except (socket.gaierror, socket.timeout):
        pass
    finally:
        socket.setdefaulttimeout(None)

    return result


def matches_ip_rules(host_ips: Iterable[ipaddress._BaseAddress], ip_set: Set[ipaddress._BaseAddress], 
                     cidrs: List[ipaddress._BaseNetwork]) -> Optional[str]:
    """Возвращает строку с описанием совпадения или None"""
    for ip in host_ips:
        # Пропускаем приватные/локальные IP
        if is_private_ip(ip):
            continue
            
        # Проверка по точному совпадению
        if ip in ip_set:
            return f"IP exact match: {ip}"
        
        # Проверка по CIDR
        for net in cidrs:
            if ip.version == net.version and ip in net:
                return f"IP in CIDR: {ip} in {net}"
    
    return None


def domain_matches_sni(host: str, sni_domains: Set[str]) -> Optional[str]:
    """Возвращает строку с описанием совпадения или None"""
    host = host.lower()
    
    # Точное совпадение
    if host in sni_domains:
        return f"Domain exact match: {host}"
    
    # Проверка поддоменов
    parts = host.split(".")
    for i in range(len(parts)):
        parent_domain = ".".join(parts[i:])
        if parent_domain in sni_domains:
            return f"Subdomain match: {host} -> {parent_domain}"
    
    return None


def check_link(link: str, sni_domains: Set[str], exact_ips: Set[ipaddress._BaseAddress], 
               cidr_rules: List[ipaddress._BaseNetwork], dns_cache: Dict[str, Set[ipaddress._BaseAddress]]) -> Tuple[str, bool, str]:
    """Проверяет одну ссылку и возвращает (link, matched, reason)"""
    try:
        host = host_from_vless(link)
        if not host:
            return (link, False, "No host extracted")

        # Проверка по доменам SNI
        domain_match = domain_matches_sni(host, sni_domains)
        if domain_match:
            log_debug(f"✓ MATCH | {link[:80]}... | {domain_match}")
            return (link, True, domain_match)

        # Проверка по IP с кешированием DNS
        if host in dns_cache:
            ips = dns_cache[host]
        else:
            ips = resolve_host_ips(host)
            dns_cache[host] = ips

        if not ips:
            log_debug(f"✗ SKIP  | {link[:80]}... | Host: {host} | No IPs resolved")
            return (link, False, f"No IPs resolved for {host}")

        # Проверка приватных IP
        private_ips = [ip for ip in ips if is_private_ip(ip)]
        if private_ips and len(private_ips) == len(ips):
            log_debug(f"✗ SKIP  | {link[:80]}... | Host: {host} | All IPs are private: {private_ips}")
            return (link, False, f"All IPs private: {private_ips}")

        ip_match = matches_ip_rules(ips, exact_ips, cidr_rules)
        if ip_match:
            log_debug(f"✓ MATCH | {link[:80]}... | Host: {host} | {ip_match}")
            return (link, True, ip_match)

        log_debug(f"✗ SKIP  | {link[:80]}... | Host: {host} | IPs: {ips} | No match")
        return (link, False, f"Host {host} with IPs {ips} - no match")

    except Exception as e:
        log_debug(f"✗ ERROR | {link[:80]}... | {str(e)}")
        return (link, False, f"Error: {e}")


def main() -> None:
    started = datetime.now(timezone.utc)
    log_step("Старт фильтрации VLESS")
    
    if ENABLE_DEBUG:
        log_step(f"Детальное логирование включено: {DEBUG_FILE}")
    
    # Удаляем старый файл, если существует
    if OUTPUT_FILE.exists():
        old_count = len([l for l in OUTPUT_FILE.read_text(encoding="utf-8").splitlines() if l.strip().startswith("vless://")])
        OUTPUT_FILE.unlink()
        log_step(f"Удалён старый файл с {old_count} ссылками")
    
    source_urls = load_source_urls()
    log_step(f"Найдено источников: {len(source_urls)}")
    
    exact_ips, cidr_rules = parse_ip_rules()
    sni_domains = load_domains()

    all_links: Set[str] = set()
    total_raw = 0
    for url in source_urls:
        try:
            content = download_text(url)
            links = parse_vless_links(content)
            total_raw += len(links)
            all_links.update(links)
            log_step(f"Источник обработан: {url} | VLESS: {len(links)}")
        except Exception as e:
            logging.exception(f"Ошибка при загрузке {url}: {e}")

    total = len(all_links)
    duplicates_removed = total_raw - total
    log_step(f"Всего собрано ссылок: {total_raw}")
    log_step(f"Удалено дубликатов: {duplicates_removed}")
    log_step(f"Уникальных ссылок для проверки: {total}")
    log_step(f"Начата проверка (параллельно в {MAX_WORKERS} потоков)")
    
    filtered_set: Set[str] = set()
    dns_cache: Dict[str, Set[ipaddress._BaseAddress]] = {}
    processed = 0
    match_reasons: Dict[str, int] = {}

    # Параллельная обработка
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_link, link, sni_domains, exact_ips, cidr_rules, dns_cache): link
            for link in all_links
        }
        
        for future in as_completed(futures):
            try:
                link, matched, reason = future.result()
                if matched:
                    filtered_set.add(link)
                    # Статистика причин совпадений
                    reason_key = reason.split(":")[0] if ":" in reason else reason
                    match_reasons[reason_key] = match_reasons.get(reason_key, 0) + 1
                
                processed += 1
                
                if processed % BATCH_SIZE == 0 or processed == total:
                    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                    rate = processed / elapsed if elapsed > 0 else 0
                    eta = (total - processed) / rate if rate > 0 else 0
                    log_step(f"Прогресс: {processed}/{total} ({processed*100//total}%) | "
                           f"Совпадений: {len(filtered_set)} | "
                           f"Скорость: {rate:.1f} ссылок/сек | "
                           f"ETA: {eta/60:.1f} мин")
            except Exception as e:
                logging.error(f"Ошибка обработки: {e}")

    # Сортировка результатов
    filtered_list = sorted(filtered_set)
    
    OUTPUT_FILE.write_text("\n".join(filtered_list) + ("\n" if filtered_list else ""), encoding="utf-8")
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    
    log_step(f"━" * 60)
    log_step(f"СТАТИСТИКА:")
    log_step(f"  Всего ссылок собрано: {total_raw}")
    log_step(f"  Дубликатов удалено: {duplicates_removed}")
    log_step(f"  Уникальных проверено: {total}")
    log_step(f"  Прошло фильтр: {len(filtered_list)}")
    log_step(f"  Процент прохождения: {len(filtered_list)*100/total:.2f}%")
    log_step(f"  Уникальных хостов проверено: {len(dns_cache)}")
    log_step(f"")
    log_step(f"  Причины совпадений:")
    for reason, count in sorted(match_reasons.items(), key=lambda x: x[1], reverse=True):
        log_step(f"    {reason}: {count}")
    log_step(f"")
    log_step(f"  Результат сохранён: {OUTPUT_FILE}")
    if ENABLE_DEBUG:
        log_step(f"  Детальный лог: {DEBUG_FILE}")
    log_step(f"  Время выполнения: {elapsed:.2f} сек ({elapsed/60:.2f} мин)")
    log_step(f"━" * 60)


if __name__ == "__main__":
    main()

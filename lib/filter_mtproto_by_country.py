#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр MTProto-прокси по geo-стране: локальный Country MMDB (db-ip lite) + ip-api.

Скрипт читает `configs/mtproto` (по умолчанию), парсит строки mtproto-прокси и
оставляет только те, у которых countryCode endpoint == DOCKER_LOCATION_FILTER.

Важно:
 - Для `server` (IP или hostname) резолв в IPv4; страна по MMDB для IP, при пустом
   ответе MMDB - запрос к ip-api (по IP; если A-записей нет - по hostname).
 - JSON-кэш: ключи host и/или IPv4 (как в filter_configs_by_cidr_and_geo).
 - Исходный файл не изменяется; при --output-file пишется отфильтрованный список.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


sys.path.insert(0, os.getcwd())
try:
    # Рекомендуемый запуск из корня проекта: `python lib/filter_mtproto_by_country.py`
    from lib.mtproto_checker import _load_raw_lines, _parse_mtproto
    from lib.filter_configs_by_cidr_and_geo import _fill_geo_cache_mmdb
    from lib.filter_configs_by_cidr_and_geo import _resolve_ipv4_all
except ImportError:
    # fallback при запуске не из корня
    from mtproto_checker import _load_raw_lines, _parse_mtproto
    from filter_configs_by_cidr_and_geo import _fill_geo_cache_mmdb
    from filter_configs_by_cidr_and_geo import _resolve_ipv4_all


class _MinIntervalRateLimiter:
    """Глобальный минимальный интервал между стартами запросов к API."""

    def __init__(self, requests_per_minute: float) -> None:
        self._interval = 60.0 / max(1.0, float(requests_per_minute))
        self._lock = threading.Lock()
        self._earliest_next = 0.0

    def wait_turn(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._earliest_next - now)
            self._earliest_next = max(self._earliest_next, now) + self._interval
        if wait > 0:
            time.sleep(wait)


def _parse_retry_after_seconds(exc: HTTPError) -> float | None:
    try:
        ra = exc.headers.get("Retry-After")
        if not ra:
            return None
        return float(ra.strip())
    except (TypeError, ValueError):
        return None


def _geo_fetch_http(
    ip_or_host: str,
    geo_api_template: str,
    timeout: float,
    max_retries: int,
    retry_base_seconds: float,
) -> str:
    """
    Возвращает countryCode (upper) или пустую строку при ошибке/неуспехе.
    """
    url = geo_api_template.format(ip=ip_or_host)
    for attempt in range(max(1, max_retries)):
        req = Request(url, headers={"User-Agent": "XRayCheck/geo-filter"})
        try:
            with urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                if str(data.get("status", "")).lower() != "success":
                    return ""
                return (data.get("countryCode") or "").strip().upper()
        except HTTPError as e:
            if e.code == 429:
                ra = _parse_retry_after_seconds(e)
                backoff = ra if ra is not None else min(60.0, retry_base_seconds * (2**attempt))
                backoff += random.uniform(0, 0.35)
                time.sleep(backoff)
                continue
            if 500 <= e.code < 600:
                time.sleep(min(30.0, retry_base_seconds * (2**attempt)))
                continue
            return ""
        except URLError:
            time.sleep(min(15.0, retry_base_seconds * (2**attempt)))
            continue
        except Exception:
            return ""
    return ""


def _geo_lookup_parallel(
    ip_or_host: str,
    cache: dict[str, str],
    cache_lock: threading.Lock,
    rate: _MinIntervalRateLimiter,
    sem: threading.Semaphore,
    geo_api_template: str,
    timeout: float,
    jitter_delay: float,
    max_retries: int,
    retry_base_seconds: float,
) -> None:
    # Важно: возвращаемся только если в кэше уже есть НЕпустой countryCode.
    # Иначе мы могли пометить host как missing_hosts, но lookup не выполнится.
    with cache_lock:
        existing = cache.get(ip_or_host, "")
        if (existing or "").strip():
            return

    # Сдвигаем под rate limiter ДО захвата семафора.
    rate.wait_turn()

    sem.acquire()
    try:
        with cache_lock:
            existing = cache.get(ip_or_host, "")
            if (existing or "").strip():
                return
        if jitter_delay > 0:
            time.sleep(jitter_delay)

        cc = _geo_fetch_http(
            ip_or_host=ip_or_host,
            geo_api_template=geo_api_template,
            timeout=timeout,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )

        with cache_lock:
            cache[ip_or_host] = cc
    finally:
        sem.release()


def _fill_geo_cache_parallel(
    missing_hosts: list[str],
    geo_cache: dict[str, str],
    *,
    geo_api_template: str,
    geo_timeout: float,
    geo_delay: float,
    requests_per_minute: float,
    max_concurrent: int,
    max_workers: int,
    max_retries: int,
    retry_base_seconds: float,
) -> None:
    if not missing_hosts:
        return

    rate = _MinIntervalRateLimiter(requests_per_minute)
    sem = threading.Semaphore(max(1, int(max_concurrent)))
    cache_lock = threading.Lock()
    workers = min(max(1, int(max_workers)), len(missing_hosts))

    def _one(host: str) -> None:
        _geo_lookup_parallel(
            host,
            geo_cache,
            cache_lock,
            rate,
            sem,
            geo_api_template,
            geo_timeout,
            geo_delay,
            max_retries,
            retry_base_seconds,
        )

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_one, host) for host in missing_hosts]
        for fut in as_completed(futures):
            fut.result()


def _load_geo_cache(cache_file: str | None) -> dict[str, str]:
    if not cache_file or not os.path.isfile(cache_file):
        return {}
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            return {}
        out: dict[str, str] = {}
        for k, v in raw.items():
            if not isinstance(k, str):
                continue
            out[str(k)] = str(v).strip().upper()
        return out
    except Exception:
        return {}


def _save_geo_cache(cache_file: str | None, geo_cache: dict[str, str]) -> None:
    if not cache_file:
        return
    parent = os.path.dirname(cache_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(geo_cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _ip_needs_geo_lookup(ip: str, geo_cache: dict[str, str]) -> bool:
    return not (str(geo_cache.get(ip, "") or "").strip())


def _line_passes(
    host: str,
    location: str,
    host_to_ips: dict[str, list[str]],
    geo_cache: dict[str, str],
) -> bool:
    """
    Решение по строке после MMDB+HTTP: как filter_configs - any(ip)==location;
    если по всем IPv4 кода нет (ошибка/пусто), допускаем legacy-кэш только по host
    (старые geoip_cache_mtproto.json без ключей по IP).
    """
    ips = host_to_ips.get(host, [])
    if ips:
        for ip in ips:
            if (geo_cache.get(ip) or "").strip() == location:
                return True
        for ip in ips:
            cc = (geo_cache.get(ip) or "").strip()
            if cc:
                return False
        return (geo_cache.get(host) or "").strip() == location
    return (geo_cache.get(host) or "").strip() == location


def _finalize_host_entries(
    unique_hosts: list[str],
    host_to_ips: dict[str, list[str]],
    location: str,
    geo_cache: dict[str, str],
) -> None:
    """Дублируем итог по ключу host для JSON-кэша; не затираем legacy host, если по IP пусто."""
    for host in unique_hosts:
        ips = host_to_ips.get(host, [])
        if ips:
            ccs = [(geo_cache.get(ip) or "").strip() for ip in ips]
            ccs_nz = [c for c in ccs if c]
            if any(c == location for c in ccs_nz):
                geo_cache[host] = location
            elif ccs_nz:
                geo_cache[host] = ccs_nz[0]
            elif (geo_cache.get(host) or "").strip():
                pass
            else:
                geo_cache[host] = ""
        elif not (geo_cache.get(host) or "").strip():
            geo_cache[host] = ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Filter MTProto configs by geo (MMDB + ip-api), same idea as filter_configs_by_cidr_and_geo"
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default=os.path.join("configs", "mtproto"),
        help="Path to mtproto input file (default: configs/mtproto)",
    )
    parser.add_argument(
        "--geo-cache-file",
        default=os.path.join("configs", "geoip_cache_mtproto.json"),
        help="JSON cache file: ip/host -> countryCode",
    )
    parser.add_argument(
        "--geo-mmdb",
        default=(os.environ.get("GEOIP_MMDB") or "").strip(),
        metavar="PATH",
        help="Локальный Country MMDB (db-ip-country-lite и т.п.). Переменная окружения: GEOIP_MMDB.",
    )
    parser.add_argument(
        "--geo-api-url",
        default="http://ip-api.com/json/{ip}?fields=countryCode,status,message",
        help="ip-api URL template with {ip}",
    )
    parser.add_argument("--geo-timeout", type=float, default=5.0)
    parser.add_argument("--geo-delay", type=float, default=0.0)
    parser.add_argument(
        "--geo-requests-per-minute",
        type=float,
        default=45.0,
        help="Target global start rate for ip-api (~45/min).",
    )
    parser.add_argument("--geo-max-concurrent", type=int, default=6)
    parser.add_argument("--geo-workers", type=int, default=32)
    parser.add_argument("--geo-max-retries", type=int, default=4)
    parser.add_argument("--geo-retry-base-seconds", type=float, default=2.0)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Allow lines without secret (if present) in mtproto parsing.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="If set, write all passed MTProto lines into this file.",
    )
    parser.add_argument(
        "--output-top-file",
        default="",
        help="If set, write up to --top-n passed MTProto lines into this file.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=100,
        help="Top-N to write into output-top-file (preserves order).",
    )
    args = parser.parse_args()

    location = (os.environ.get("DOCKER_LOCATION_FILTER") or "").strip().upper() or "RU"
    if not os.environ.get("DOCKER_LOCATION_FILTER"):
        print("::warning::DOCKER_LOCATION_FILTER not set; defaulting to RU", flush=True)
    if len(location) < 2:
        print(f"::error::Invalid DOCKER_LOCATION_FILTER={location!r}", flush=True)
        return 1

    input_path = args.input_file
    if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
        print(f"{input_path} missing or empty - nothing to filter.")
        return 0

    raw_lines = _load_raw_lines(input_path)
    parsed_items: list[tuple[str, str]] = []
    for line in raw_lines:
        parsed = _parse_mtproto(line, strict=True, allow_incomplete=bool(args.allow_incomplete))
        if not parsed:
            continue
        host, _port, _normalized, _key = parsed
        parsed_items.append((line, host))

    total_valid = len(parsed_items)
    if total_valid == 0:
        print("No valid MTProto proxies parsed from input.")
        return 0

    unique_hosts = sorted({host for _line, host in parsed_items if host})

    geo_cache = _load_geo_cache(args.geo_cache_file)
    # Backward-compat: если есть старый ru-кэш и новый кэш не заполнен - подтянем его.
    fallback_ru_cache = os.path.join("configs", "geoip_cache_mtproto_ru.json")
    if not geo_cache and args.geo_cache_file != fallback_ru_cache and os.path.isfile(fallback_ru_cache):
        geo_cache = _load_geo_cache(fallback_ru_cache)

    host_to_ips: dict[str, list[str]] = {}
    for host in unique_hosts:
        host_to_ips[host] = _resolve_ipv4_all(host)

    unique_ips_set: set[str] = set()
    for ips in host_to_ips.values():
        unique_ips_set.update(ips)
    unique_ips = sorted(unique_ips_set)

    def _needs_lookup_host(h: str) -> bool:
        return not (geo_cache.get(h, "") or "").strip()

    missing_ips = [ip for ip in unique_ips if _ip_needs_geo_lookup(ip, geo_cache)]

    mmdb_path = (args.geo_mmdb or "").strip()
    if missing_ips and mmdb_path:
        if os.path.isfile(mmdb_path):
            print(
                f"Geo MMDB: {len(missing_ips)} IPs via {mmdb_path} (unique_hosts={len(unique_hosts)})",
                flush=True,
            )
            _fill_geo_cache_mmdb(missing_ips, geo_cache, mmdb_path)
        else:
            print(
                f"::warning::--geo-mmdb file missing: {mmdb_path}, using ip-api only for those IPs",
                flush=True,
            )

    missing_ips = [ip for ip in unique_ips if _ip_needs_geo_lookup(ip, geo_cache)]
    if missing_ips:
        print(
            f"Geo HTTP (ip-api): missing_ips={len(missing_ips)} (unique_hosts={len(unique_hosts)}, "
            f"rpm={args.geo_requests_per_minute})",
            flush=True,
        )
        _fill_geo_cache_parallel(
            missing_ips,
            geo_cache,
            geo_api_template=args.geo_api_url,
            geo_timeout=args.geo_timeout,
            geo_delay=args.geo_delay,
            requests_per_minute=args.geo_requests_per_minute,
            max_concurrent=args.geo_max_concurrent,
            max_workers=args.geo_workers,
            max_retries=args.geo_max_retries,
            retry_base_seconds=args.geo_retry_base_seconds,
        )

    missing_host_only = [h for h in unique_hosts if not host_to_ips[h] and _needs_lookup_host(h)]
    if missing_host_only:
        print(
            f"Geo HTTP (ip-api, hostname only): count={len(missing_host_only)}",
            flush=True,
        )
        _fill_geo_cache_parallel(
            missing_host_only,
            geo_cache,
            geo_api_template=args.geo_api_url,
            geo_timeout=args.geo_timeout,
            geo_delay=args.geo_delay,
            requests_per_minute=args.geo_requests_per_minute,
            max_concurrent=args.geo_max_concurrent,
            max_workers=args.geo_workers,
            max_retries=args.geo_max_retries,
            retry_base_seconds=args.geo_retry_base_seconds,
        )

    passed_lines: list[str] = [
        line
        for line, host in parsed_items
        if _line_passes(host, location, host_to_ips, geo_cache)
    ]

    _finalize_host_entries(unique_hosts, host_to_ips, location, geo_cache)
    _save_geo_cache(args.geo_cache_file, geo_cache)

    passed = len(passed_lines)

    if args.output_file:
        parent = os.path.dirname(args.output_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(passed_lines) + ("\n" if passed_lines else ""))

    if args.output_top_file:
        parent = os.path.dirname(args.output_top_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        top_lines = passed_lines[: max(0, int(args.top_n))]
        with open(args.output_top_file, "w", encoding="utf-8") as f:
            f.write("\n".join(top_lines) + ("\n" if top_lines else ""))

    print(
        f"MTProto geo filter: location={location} passed={passed} / total={total_valid} "
        f"(unique_hosts={len(unique_hosts)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


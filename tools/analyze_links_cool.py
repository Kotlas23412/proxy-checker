#!/usr/bin/env python3
import json
import os
import socket
import sys
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, os.getcwd())
from lib.parsing import normalize_proxy_link, parse_proxy_url


ROOT = Path(".")
LINKS_FILE = ROOT / "linksnew copy.txt"
WORK_DIR = ROOT / "configs" / ".links_cool"
WORK_DIR.mkdir(parents=True, exist_ok=True)
MMDB_PATH = ROOT / "configs" / "dbip-country-lite.mmdb"
GEO_CACHE_PATH = ROOT / "configs" / "geoip_cache.json"


def read_urls(path: Path, limit: int = 16) -> list[str]:
    urls = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s)
        if len(urls) >= limit:
            break
    return urls


def download_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "XRayCheck/analyze-links-cool"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read().decode("utf-8", errors="replace")


def extract_config_lines(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        s = raw.strip().replace("\r", "")
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def host_from_line(line: str) -> str:
    link = line.split("#", 1)[0].strip() if "#" in line else line.strip().split(maxsplit=1)[0].strip()
    parsed = parse_proxy_url(link)
    if isinstance(parsed, dict):
        return (parsed.get("address") or "").strip()
    return ""


def resolve_ipv4_all(host: str) -> list[str]:
    if not host:
        return []
    try:
        import ipaddress

        ip_obj = ipaddress.ip_address(host)
        return [str(ip_obj)] if ip_obj.version == 4 else []
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return []
    ips = sorted({i[4][0] for i in infos if i and i[4] and i[4][0]})
    return ips


def load_geo_cache(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(raw, dict):
            return {}
        return {str(k): str(v).strip().upper() for k, v in raw.items() if isinstance(k, str)}
    except Exception:
        return {}


def save_geo_cache(path: Path, cache: dict[str, str]) -> None:
    path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def fill_geo_with_mmdb(ips: list[str], cache: dict[str, str], mmdb_path: Path) -> None:
    if not mmdb_path.exists():
        return
    try:
        import geoip2.database
        import geoip2.errors
    except Exception:
        return
    with geoip2.database.Reader(str(mmdb_path)) as reader:
        for ip in ips:
            if cache.get(ip, "").strip():
                continue
            try:
                rec = reader.country(ip)
                cache[ip] = (rec.country.iso_code or "").strip().upper()
            except Exception:
                cache[ip] = ""


def main() -> int:
    urls = read_urls(LINKS_FILE, 16)
    if not urls:
        print("No URLs found in linksnew copy.txt")
        return 1

    per_source_lines: dict[str, list[str]] = {}
    fetch_errors: dict[str, str] = {}
    for idx, url in enumerate(urls, 1):
        try:
            txt = download_text(url)
            lines = extract_config_lines(txt)
            per_source_lines[url] = lines
            (WORK_DIR / f"source_{idx:02d}.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        except Exception as e:
            fetch_errors[url] = str(e)
            per_source_lines[url] = []

    # normalize within source
    per_source_norms: dict[str, set[str]] = {}
    per_source_host_by_norm: dict[str, dict[str, str]] = {}
    all_hosts: set[str] = set()
    for url, lines in per_source_lines.items():
        norms: set[str] = set()
        host_by_norm: dict[str, str] = {}
        for line in lines:
            link = line.split("#", 1)[0].strip() if "#" in line else line.strip().split(maxsplit=1)[0].strip()
            norm = normalize_proxy_link(link)
            if not norm or norm in norms:
                continue
            host = host_from_line(line)
            norms.add(norm)
            host_by_norm[norm] = host
            if host:
                all_hosts.add(host)
        per_source_norms[url] = norms
        per_source_host_by_norm[url] = host_by_norm

    # resolve hosts -> ipv4s
    host_list = sorted(all_hosts)
    host_to_ips: dict[str, list[str]] = {}
    if host_list:
        workers = min(64, len(host_list))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for host, ips in zip(host_list, ex.map(resolve_ipv4_all, host_list)):
                host_to_ips[host] = ips

    # geo cache
    geo_cache = load_geo_cache(GEO_CACHE_PATH)
    all_ips = sorted({ip for ips in host_to_ips.values() for ip in ips})
    fill_geo_with_mmdb(all_ips, geo_cache, MMDB_PATH)
    # Remaining missing IPs stay empty (unknown country) for this analysis run.
    save_geo_cache(GEO_CACHE_PATH, geo_cache)

    # RU pass sets per source
    per_source_ru: dict[str, set[str]] = {}
    for url, norms in per_source_norms.items():
        host_by_norm = per_source_host_by_norm[url]
        passed = set()
        for norm in norms:
            host = host_by_norm.get(norm, "")
            ips = host_to_ips.get(host, [])
            if not ips:
                continue
            if any((geo_cache.get(ip, "") or "") == "RU" for ip in ips):
                passed.add(norm)
        per_source_ru[url] = passed

    # duplicate analysis on RU-passed sets between sources
    norm_to_sources: dict[str, set[str]] = defaultdict(set)
    for url, norms in per_source_ru.items():
        for n in norms:
            norm_to_sources[n].add(url)

    source_stats = []
    for url in urls:
        ru_set = per_source_ru.get(url, set())
        shared = sum(1 for n in ru_set if len(norm_to_sources[n]) > 1)
        unique_only = len(ru_set) - shared
        dup_ratio = (shared / len(ru_set)) if ru_set else 0.0
        source_stats.append(
            {
                "url": url,
                "downloaded_lines": len(per_source_lines.get(url, [])),
                "ru_pass": len(ru_set),
                "shared_ru": shared,
                "unique_ru": unique_only,
                "dup_ratio": dup_ratio,
                "fetch_error": fetch_errors.get(url, ""),
            }
        )

    # Greedy recommendation: maximize new RU unique coverage
    selected: list[str] = []
    covered: set[str] = set()
    remaining = set(urls)
    while remaining:
        best_url = None
        best_gain = -1
        best_ratio = 1.0
        for url in remaining:
            ru_set = per_source_ru.get(url, set())
            gain = len(ru_set - covered)
            ratio = source_stats[urls.index(url)]["dup_ratio"]
            if gain > best_gain or (gain == best_gain and ratio < best_ratio):
                best_gain = gain
                best_ratio = ratio
                best_url = url
        if not best_url:
            break
        # stop when marginal gain is tiny (<=2 new RU configs)
        if best_gain <= 2:
            break
        selected.append(best_url)
        covered |= per_source_ru.get(best_url, set())
        remaining.remove(best_url)

    # Ensure we don't output empty recommendation
    if not selected:
        selected = [s["url"] for s in sorted(source_stats, key=lambda x: (-x["unique_ru"], x["dup_ratio"]))[:5]]

    # write links_cool
    links_cool_path = ROOT / "links_cool"
    links_cool_path.write_text("\n".join(selected) + ("\n" if selected else ""), encoding="utf-8")

    # report json
    total_ru_sum = sum(len(per_source_ru.get(u, set())) for u in urls)
    total_ru_unique = len(set().union(*(per_source_ru.get(u, set()) for u in urls))) if urls else 0
    result = {
        "urls_total": len(urls),
        "total_ru_sum_per_source": total_ru_sum,
        "total_ru_unique_across_sources": total_ru_unique,
        "recommended_count": len(selected),
        "recommended_urls": selected,
        "source_stats": sorted(source_stats, key=lambda x: (-x["dup_ratio"], -x["ru_pass"])),
    }
    (WORK_DIR / "analysis_result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


import urllib.request
import urllib.parse
import json
import random
import re
import os
import subprocess
import time

# --- Настройки ---
SNI_URL = "https://raw.githubusercontent.com/Kotlas23412/proxy-checker/refs/heads/main/sni.txt"
SOURCES_FILE = "checkproxis.txt"
LIMIT_OUT = 500
LIMIT_TEST = 1000 
OUTPUT_DIR = "proxies"

def get_sni_list():
    try:
        content = urllib.request.urlopen(SNI_URL).read().decode('utf-8')
        return [line.strip().lower() for line in content.splitlines() if line.strip()]
    except Exception as e:
        print(f"[ОШИБКА] Не удалось загрузить SNI: {e}")
        return ["yandex.ru", "vk.com", "gosuslugi.ru"]

def clean_remark(proxy_link):
    if "#" not in proxy_link: return proxy_link
    base, remark = proxy_link.split("#", 1)
    remark = urllib.parse.unquote(remark)
    country_match = re.search(r'([A-Z]{2}|[\U0001F1E6-\U0001F1FF]{2})', remark)
    country = country_match.group(1) if country_match else ""
    company = ""
    if " - " in remark:
        parts = remark.split(" - ", 1)
        if len(parts) > 1:
            words = parts[1].split()
            company = " ".join(words[:2])
    company = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '', company)
    company = re.sub(r't\.me[^\s]+', '', company)
    company = re.sub(r'[\[\]]', '', company).strip()
    new_remark = f"{country}-{company}" if country and company else (country if country else "Proxy")
    return f"{base}#{new_remark}"

def inject_random_sni(proxy_link, sni_list):
    base, remark = proxy_link.split("#", 1) if "#" in proxy_link else (proxy_link, "Injected-SNI")
    random_sni = random.choice(sni_list)
    if re.search(r'([?&])sni=[^&#]+', base):
        base = re.sub(r'([?&])sni=[^&#]+', rf'\g<1>sni={random_sni}', base)
    else:
        sep = "&" if "?" in base else "?"
        base += f"{sep}sni={random_sni}"
    return f"{base}#{remark}"

def extract_sni(proxy_link):
    match = re.search(r'([?&])sni=([^&#]+)', proxy_link)
    return match.group(2).lower() if match else ""

def test_proxies(proxies, phase_name, test_url):
    if not proxies: return []
    if len(proxies) > LIMIT_TEST:
        proxies = random.sample(proxies, LIMIT_TEST)
        print(f"   [INFO] Случайные {LIMIT_TEST} для теста.")

    # 1. Записываем ноды для теста
    with open("temp_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(proxies))
    
    # 2. Создаем файл конфигурации config.json для чекера
    # Это заставит его тестировать нужный нам URL и выдавать JSON
    checker_config = {
        "testUrl": test_url,
        "outFormat": "json",
        "outPath": "out.json",
        "threads": 100,
        "timeout": 3,
        "pingMethod": "tcping"
    }
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(checker_config, f)

    # Удаляем старый результат
    if os.path.exists("out.json"): os.remove("out.json")

    # 3. Запускаем чекер через флаг -test (как указано в Usage)
    cmd = "./lite -test temp_nodes.txt"
    
    try:
        print(f"   [*] Запуск {phase_name} ({test_url})...")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        
        # Чекер этой версии часто создает файлы с именем типа 'out.json' или 'results.json'
        # или добавляет дату. Попробуем найти любой .json файл, если out.json нет.
        output_file = "out.json"
        if not os.path.exists(output_file):
            all_files = [f for f in os.listdir('.') if f.endswith('.json') and f != 'config.json']
            if all_files:
                output_file = all_files[0]

        if not os.path.exists(output_file):
            print(f"   [ОШИБКА] Чекер не выдал JSON результат.")
            return []

        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            # В разных версиях JSON может быть списком или словарем
            nodes = data.get("nodes", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            
            valid_nodes = [n for n in nodes if n.get("ping", 0) > 0]
            valid_nodes.sort(key=lambda x: x.get("ping", 9999))
            working = [n.get("link") for n in valid_nodes if n.get("link")]
            
        print(f"   -> Успешно: {len(working)} из {len(proxies)}")
        
        # Чистим за собой
        if os.path.exists(output_file): os.remove(output_file)
        
        return working
    except Exception as e:
        print(f"   [!] Ошибка чекера: {e}")
        return []

def main():
    print("="*60)
    print("1. ЗАГРУЗКА")
    print("="*60)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sni_list = get_sni_list()
    sni_set = set(sni_list)

    raw_proxies = set()
    with open(SOURCES_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            data = urllib.request.urlopen(req).read().decode('utf-8').splitlines()
            count = 0
            for line in data:
                line = line.strip()
                if any(line.startswith(prefix) for prefix in ["vless://", "hysteria2://", "hy2://"]):
                    raw_proxies.add(clean_remark(line))
                    count += 1
            print(f"Скачано {count} прокси из: {url.split('/')[-1]}")
        except Exception as e:
            print(f"[!] Ошибка {url}: {e}")

    print(f"\nИТОГО уникальных: {len(raw_proxies)}\n")

    categories = {
        "vless_xray.txt": [],
        "vless_reality_native_sni.txt": [],
        "vless_reality_injected_sni.txt": [],
        "hysteria2.txt": []
    }

    for p in raw_proxies:
        if p.startswith("hy2") or p.startswith("hysteria2"):
            categories["hysteria2.txt"].append(p)
        elif p.startswith("vless://"):
            if "security=reality" in p:
                if extract_sni(p) in sni_set:
                    categories["vless_reality_native_sni.txt"].append(p)
                else:
                    categories["vless_reality_injected_sni.txt"].append(inject_random_sni(p, sni_list))
            else:
                categories["vless_xray.txt"].append(p)

    print("="*60)
    print("2. ТЕСТИРОВАНИЕ")
    print("="*60)

    for filename, proxies in categories.items():
        if not proxies: continue
        print(f"\n[*] КАТЕГОРИЯ: {filename} ({len(proxies)} шт.)")
        random.shuffle(proxies)
        
        cf_passed = test_proxies(proxies, "CF-Check", "http://cp.cloudflare.com/generate_204")
        if cf_passed:
            ya_passed = test_proxies(cf_passed, "YA-Check", "http://ya.ru")
        else:
            ya_passed = []
        
        final_list = ya_passed[:LIMIT_OUT]
        with open(os.path.join(OUTPUT_DIR, filename), "w", encoding="utf-8") as f:
            f.write("\n".join(final_list))
        print(f"   [OK] Финальный список: {len(final_list)}")

if __name__ == "__main__":
    main()

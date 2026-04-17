import urllib.request
import urllib.parse
import json
import random
import re
import os
import subprocess

# --- Настройки ---
SNI_URL = "https://raw.githubusercontent.com/Kotlas23412/proxy-checker/refs/heads/main/sni.txt"
SOURCES_FILE = "checkproxis.txt"
LIMIT = 500

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
    if not proxies: 
        return []
    
    with open("temp_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(proxies))
    
    # Запускаем чекер
    cmd = f"./lite --config temp_nodes.txt --test {test_url} --timeout 3000 --output result.json"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    working = []
    try:
        with open("result.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            valid_nodes = [n for n in data.get("nodes", []) if n.get("ping", 0) > 0]
            valid_nodes.sort(key=lambda x: x.get("ping", 9999))
            working = [n.get("link") for n in valid_nodes]
    except Exception as e:
        print(f"   [!] Ошибка чтения результатов: {e}")
    
    print(f"   -> [{phase_name}] Успешно ответили: {len(working)} из {len(proxies)}")
    return working

def main():
    print("="*50)
    print("1. ЗАГРУЗКА И ПАРСИНГ")
    print("="*50)
    
    sni_list = get_sni_list()
    sni_set = set(sni_list)
    print(f"Загружено {len(sni_list)} SNI для проверки из РФ.")

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
                if line.startswith("vless://") or line.startswith("hysteria2://") or line.startswith("hy2://"):
                    raw_proxies.add(clean_remark(line))
                    count += 1
            print(f"Скачано {count} прокси из: {url.split('/')[-1]}")
        except Exception as e:
            print(f"[ОШИБКА] Не удалось прочитать {url}: {e}")

    print(f"\nВСЕГО уникальных ссылок собрано: {len(raw_proxies)}\n")

    # Списки
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
                current_sni = extract_sni(p)
                if current_sni in sni_set:
                    categories["vless_reality_native_sni.txt"].append(p)
                else:
                    categories["vless_reality_injected_sni.txt"].append(inject_random_sni(p, sni_list))
            else:
                categories["vless_xray.txt"].append(p)

    print("="*50)
    print("2. РАСПРЕДЕЛЕНИЕ ПО КАТЕГОРИЯМ")
    print("="*50)
    for cat, items in categories.items():
        print(f" - {cat}: {len(items)} шт.")

    print("\n" + "="*50)
    print("3. ДВОЙНАЯ ПРОВЕРКА ПРОКСИ (Cloudflare -> Yandex)")
    print("="*50)

    for filename, proxies in categories.items():
        if not proxies:
            print(f"\nПропуск {filename} (список пуст).")
            continue
            
        print(f"\n--- Тестируем категорию: {filename} ---")
        
        # ЭТАП 1: Cloudflare
        cf_passed = test_proxies(proxies, "Этап 1: Cloudflare", "http://cp.cloudflare.com/generate_204")
        
        # ЭТАП 2: Yandex
        if cf_passed:
            ya_passed = test_proxies(cf_passed, "Этап 2: Yandex.ru", "http://ya.ru")
        else:
            ya_passed = []
            print("   -> [Этап 2: Yandex.ru] Пропущено, никто не прошел первый этап.")
        
        # Обрезка до 500 и сохранение
        final_list = ya_passed[:LIMIT]
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(final_list))
        
        print(f"   === ИТОГ: Сохранено {len(final_list)} рабочих нод в {filename} ===")

if __name__ == "__main__":
    main()

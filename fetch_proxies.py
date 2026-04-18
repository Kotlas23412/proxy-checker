import json
import urllib.request
from datetime import datetime, timezone, timedelta
import base64

# Список ссылок на JSON файлы с прокси
URLS = [
    "https://raw.githubusercontent.com/tiagorrg/vless-checker/refs/heads/main/docs/keys.json",
    "https://raw.githubusercontent.com/Kotlas23412/vless-checker/refs/heads/main/docs/keys.json"
]

def extract_proxies(data):
    """Рекурсивно ищет все строки, начинающиеся с vless://, hysteria2:// или hy2:// в JSON"""
    links = set()
    # Список поддерживаемых протоколов
    protocols = ('vless://', 'hysteria2://', 'hy2://')
    
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, str) and v.startswith(protocols):
                links.add(v)
            else:
                links.update(extract_proxies(v))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str) and item.startswith(protocols):
                links.add(item)
            else:
                links.update(extract_proxies(item))
    return links

def main():
    all_proxies = set()

    for url in URLS:
        print(f"Загрузка данных из: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8')
                data = json.loads(content)
                found = extract_proxies(data)
                all_proxies.update(found)
                print(f"Найдено прокси в этом источнике: {len(found)}")
        except Exception as e:
            print(f"Ошибка при обработке {url}: {e}")

    # Превращаем в список и сортируем
    proxies = list(all_proxies)
    proxies.sort()

    # Получаем текущее время (МСК UTC+3)
    tz = timezone(timedelta(hours=3))
    now = datetime.now(tz)
    dt_str = now.strftime("%d.%m.%Y %H:%M")

    # Формируем заголовок в формате Base64
    raw_title = f"Все рабочие (VLESS+HY2) 🔧 {dt_str}".encode('utf-8')
    b64_title = base64.b64encode(raw_title).decode('utf-8')

    # Формируем итоговый текстовый файл
    output = [
        f"# profile-title: base64:{b64_title}",
        "# profile-update-interval: 1",
        f"# Последнее обновление: {dt_str}",
        f"# Общее количество прокси: {len(proxies)}",
        "# Источники: tiagorrg & Kotlas23412",
        "",
        "# === BEGIN AutoPilot Best ==="
    ]

    output.extend(proxies)
    output.append("# === END AutoPilot Best ===")
    output.append("") 

    # Сохраняем в файл
    with open("proxies.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output))
        
    print(f"Успешно обновлено! Всего уникальных прокси: {len(proxies)}")

if __name__ == "__main__":
    main()

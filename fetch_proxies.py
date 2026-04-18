import json
import urllib.request
from datetime import datetime, timezone, timedelta
import base64

# Ссылка на JSON с вашими прокси
"""URL = "https://raw.githubusercontent.com/tiagorrg/vless-checker/refs/heads/main/docs/keys.json""""
URL = "https://raw.githubusercontent.com/Kotlas23412/vless-checker/refs/heads/main/docs/keys.json"

def extract_vless(data):
    """Рекурсивно ищет все строки, начинающиеся с vless:// в JSON"""
    links = set()
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and v.startswith('vless://'):
                links.add(v)
            else:
                links.update(extract_vless(v))
    elif isinstance(data, list):
        for item in data:
            links.update(extract_vless(item))
    return links

def main():
    # Скачиваем JSON
    req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Ошибка при скачивании или парсинге JSON: {e}")
        return

    # Достаем все уникальные vless ссылки
    proxies = list(extract_vless(data))
    
    # Сортируем для красивого вывода (необязательно)
    proxies.sort()

    # Получаем текущее время (в часовом поясе Москвы UTC+3, как в примере)
    tz = timezone(timedelta(hours=3))
    now = datetime.now(tz)
    dt_str = now.strftime("%d.%m.%Y %H:%M")

    # Формируем заголовок в формате Base64, чтобы время там тоже обновлялось
    raw_title = f"Все рабочие (Тест) 🔧 {dt_str}".encode('utf-8')
    b64_title = base64.b64encode(raw_title).decode('utf-8')

    # Формируем итоговый текстовый файл
    output = [
        f"# profile-title: base64:{b64_title}",
        "# profile-update-interval: 1",
        f"# Последнее обновление: {dt_str}",
        f"# Общее количество прокси: {len(proxies)}",
        "# Последние обновленные группы: AutoPilot Best",
        "",
        "# === BEGIN AutoPilot Best ==="
    ]

    output.extend(proxies)
    output.append("# === END AutoPilot Best ===")
    output.append("") # Пустая строка в конце файла

    # Сохраняем в файл
    with open("proxies.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output))
        
    print(f"Успешно обновлено! Найдено прокси: {len(proxies)}")

if __name__ == "__main__":
    main()

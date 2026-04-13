#!/usr/bin/env python3
import json
import urllib.parse
import os

def create_v2ray_config(outbound_data, remark):
    """Создает полную V2Ray конфигурацию из данных outbound"""
    
    config = {
        "log": {
            "loglevel": "warning"
        },
        "remarks": remark,
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "udp": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                }
            },
            {
                "port": 10809,
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                }
            }
        ],
        "outbounds": [
            outbound_data,
            {
                "tag": "direct",
                "protocol": "freedom"
            },
            {
                "tag": "block",
                "protocol": "blackhole"
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "regexp:.*\\.ru$",
                        "regexp:.*\\.рф$",
                        "regexp:.*\\.su$",
                        "domain:yandex.ru",
                        "domain:yandex.net",
                        "domain:ya.ru",
                        "domain:vk.com",
                        "domain:mail.ru",
                        "domain:sberbank.ru",
                        "domain:gosuslugi.ru"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "geoip:ru",
                        "geoip:private"
                    ]
                },
                {
                    "type": "field",
                    "protocol": [
                        "bittorrent"
                    ],
                    "outboundTag": "direct"
                }
            ]
        }
    }
    
    return config

def process_outbound(outbound, remark, idx):
    """Обрабатывает один outbound и возвращает ссылку и конфиг"""
    
    protocol = outbound.get('protocol', '')
    
    # Пропускаем не-VLESS протоколы (только VLESS)
    if protocol != 'vless':
        return None, None
        
    settings = outbound.get('settings', {})
    vnext_list = settings.get('vnext', [])
    
    if not vnext_list:
        return None, None
        
    vnext = vnext_list[0]
    address = vnext.get('address', '')
    port = vnext.get('port', 443)
    
    users = vnext.get('users', [])
    if not users:
        return None, None
        
    user = users[0]
    user_id = user.get('id', '')
    encryption = user.get('encryption', 'none')
    flow = user.get('flow', '')
    
    stream_settings = outbound.get('streamSettings', {})
    network = stream_settings.get('network', 'tcp')
    security = stream_settings.get('security', 'none')
    
    # Создаем новый outbound для итоговой конфигурации
    new_outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "encryption": encryption
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": network
        }
    }
    
    # Добавляем flow если есть
    if flow:
        new_outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow
        # Добавляем fragment для xtls-rprx-vision
        if "vision" in flow.lower():
            new_outbound["fragment"] = {
                "packets": "tlshello",
                "length": "10-30",
                "interval": "10-20"
            }
    
    # Базовые параметры для ссылки
    params = {
        'type': network,
        'encryption': encryption,
    }
    
    if flow:
        params['flow'] = flow
    
    # Reality настройки
    if security == 'reality':
        reality = stream_settings.get('realitySettings', {})
        new_outbound["streamSettings"]["security"] = "reality"
        
        reality_settings = {}
        
        sni = reality.get('serverName', '')
        if sni:
            params['sni'] = sni
            reality_settings['serverName'] = sni
            
        fp = reality.get('fingerprint', 'chrome')
        params['fp'] = fp
        reality_settings['fingerprint'] = fp
        
        pbk = reality.get('publicKey', '')
        if pbk:
            params['pbk'] = pbk
            reality_settings['publicKey'] = pbk
            
        sid = reality.get('shortId', '')
        if sid:
            params['sid'] = sid
        reality_settings['shortId'] = sid
        
        # Добавляем spiderX если есть
        spiderX = reality.get('spiderX', '')
        if spiderX:
            params['spx'] = spiderX
            reality_settings['spiderX'] = spiderX
        
        new_outbound["streamSettings"]["realitySettings"] = reality_settings
    
    # TLS настройки
    elif security == 'tls':
        params['security'] = 'tls'
        tls_settings = stream_settings.get('tlsSettings', {})
        
        new_outbound["streamSettings"]["security"] = "tls"
        tls_config = {}
        
        sni = tls_settings.get('serverName', '')
        if sni:
            params['sni'] = sni
            tls_config['serverName'] = sni
            
        fp = tls_settings.get('fingerprint', 'chrome')
        params['fp'] = fp
        tls_config['fingerprint'] = fp
        
        alpn = tls_settings.get('alpn', [])
        if alpn:
            params['alpn'] = ','.join(alpn)
            tls_config['alpn'] = alpn
        
        new_outbound["streamSettings"]["tlsSettings"] = tls_config
    
    # WebSocket настройки
    if network == 'ws':
        ws_settings = stream_settings.get('wsSettings', {})
        ws_config = {}
        
        host = ws_settings.get('headers', {}).get('Host', '')
        if host:
            params['host'] = host
            ws_config['headers'] = {"Host": host}
            
        path = ws_settings.get('path', '/')
        params['path'] = path
        ws_config['path'] = path
        
        new_outbound["streamSettings"]["wsSettings"] = ws_config
    
    # XHTTP настройки
    elif network == 'xhttp':
        xhttp_settings = stream_settings.get('xhttpSettings', {})
        xhttp_config = {}
        
        host = xhttp_settings.get('host', '')
        if host:
            params['host'] = host
            xhttp_config['host'] = host
            
        path = xhttp_settings.get('path', '/')
        params['path'] = path
        xhttp_config['path'] = path
        
        mode = xhttp_settings.get('mode', 'auto')
        params['mode'] = mode
        xhttp_config['mode'] = mode
        
        new_outbound["streamSettings"]["xhttpSettings"] = xhttp_config
    
    # TCP настройки (пустые, но нужны для структуры)
    elif network == 'tcp':
        tcp_settings = stream_settings.get('tcpSettings', {})
        if tcp_settings:
            new_outbound["streamSettings"]["tcpSettings"] = tcp_settings
    
    # Формируем query string для ссылки
    query = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    
    # Формируем имя
    tag = outbound.get('tag', f'proxy-{idx+1}')
    name = f"{remark} - {tag}"
    name_encoded = urllib.parse.quote(name)
    
    # Собираем ссылку
    vless_link = f"vless://{user_id}@{address}:{port}/?{query}#{name_encoded}"
    
    # Создаем полную конфигурацию
    full_config = create_v2ray_config(new_outbound, name)
    
    return vless_link, full_config

def json_to_vless(config_data, source_name="Proxy"):
    """Конвертирует JSON конфигурацию V2Ray в VLESS ссылки и конфиги"""
    
    vless_links = []
    json_configs = []
    
    try:
        config = json.loads(config_data)
        
        # Получаем remarks для имени конфигурации
        remark = config.get('remarks', source_name)
        
        # Обрабатываем все outbounds
        outbounds = config.get('outbounds', [])
        
        for idx, outbound in enumerate(outbounds):
            link, json_config = process_outbound(outbound, remark, idx)
            
            if link and json_config:
                vless_links.append(link)
                json_configs.append(json_config)
                
                address = outbound.get('settings', {}).get('vnext', [{}])[0].get('address', 'unknown')
                port = outbound.get('settings', {}).get('vnext', [{}])[0].get('port', '?')
                tag = outbound.get('tag', f'proxy-{idx+1}')
                print(f"  ✓ Создана конфигурация для {tag}: {address}:{port}")
    
    except json.JSONDecodeError as e:
        print(f"  ✗ Ошибка парсинга JSON: {e}")
    except Exception as e:
        print(f"  ✗ Ошибка: {e}")
        import traceback
        traceback.print_exc()
    
    return vless_links, json_configs

def split_json_configs(content):
    """Разделяет текст на отдельные JSON объекты"""
    configs = []
    stack = []
    current = ""
    in_string = False
    escape = False
    
    for char in content:
        if escape:
            current += char
            escape = False
            continue
            
        if char == '\\':
            escape = True
            current += char
            continue
            
        if char == '"' and not escape:
            in_string = not in_string
            current += char
            continue
            
        if in_string:
            current += char
            continue
            
        if char == '{':
            if len(stack) == 0:
                current = ""
            stack.append('{')
            current += char
        elif char == '}':
            current += char
            if stack:
                stack.pop()
            if len(stack) == 0 and current.strip():
                configs.append(current.strip())
                current = ""
        else:
            if len(stack) > 0:
                current += char
    
    return configs

def process_config_file(filename, output_filename, source_name):
    """Обрабатывает один файл конфигурации"""
    print(f"\n{'='*60}")
    print(f"Обработка файла: {filename}")
    print(f"{'='*60}")
    
    # Читаем файл с конфигурациями
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"⚠️  Файл {filename} не найден, пропускаем...")
        return 0
    
    print(f"\n📄 Размер файла: {len(content)} символов")
    
    # Разделяем на отдельные JSON объекты
    configs = split_json_configs(content)
    
    print(f"📦 Найдено {len(configs)} JSON конфигураций\n")
    
    # Конвертируем все конфигурации
    all_links = []
    
    for i, config in enumerate(configs, 1):
        print(f"Обработка конфигурации {i}/{len(configs)}...")
        links, _ = json_to_vless(config, source_name)
        all_links.extend(links)
    
    # Записываем результаты
    if all_links:
        with open(output_filename, 'w', encoding='utf-8') as f:
            for link in all_links:
                f.write(link + '\n')
        
        print(f"\n{'='*60}")
        print(f"✅ Успешно создано:")
        print(f"   📝 {len(all_links)} VLESS ссылок → {output_filename}")
        print(f"{'='*60}")
        
        print(f"\n🔗 Первые 3 ссылки из {output_filename}:")
        for i, link in enumerate(all_links[:3], 1):
            print(f"{i}. {link[:80]}...")
    else:
        print(f"\n❌ Не удалось сгенерировать ни одной ссылки из {filename}!")
        print("Проверьте формат конфигураций в файле")
    
    return len(all_links)

def main():
    print("=" * 60)
    print("V2Ray Multi-Config Converter")
    print("=" * 60)
    
    total_links = 0
    all_json_configs = []
    
    # Обработка configs.txt → output.txt
    count1 = process_config_file('configs.txt', 'output.txt', 'Config1')
    total_links += count1
    
    # Обработка configs2.txt → output2.txt
    count2 = process_config_file('configs2.txt', 'output2.txt', 'Config2')
    total_links += count2
    
    # Создаем объединенный JSON с обеими конфигурациями
    for filename, source_name in [('configs.txt', 'Config1'), ('configs2.txt', 'Config2')]:
        if os.path.exists(filename):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                configs = split_json_configs(content)
                for config in configs:
                    _, json_configs = json_to_vless(config, source_name)
                    all_json_configs.extend(json_configs)
            except:
                pass
    
    # Сохраняем объединенный JSON
    if all_json_configs:
        with open('output.json', 'w', encoding='utf-8') as f:
            json.dump(all_json_configs, f, ensure_ascii=False, indent=2)
        print(f"\n📋 Сохранено {len(all_json_configs)} JSON конфигураций → output.json")
    
    print(f"\n{'='*60}")
    print(f"🎉 Всего обработано: {total_links} VLESS конфигураций")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()

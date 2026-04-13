#!/usr/bin/env python3
import json
import urllib.parse
import os
import re

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

# Глобальная база данных Reality параметров из configs2.txt
REALITY_DATABASE = {}

def load_reality_database(filename='configs2.txt'):
    """Загружает Reality параметры из полной конфигурации"""
    global REALITY_DATABASE
    
    if not os.path.exists(filename):
        return
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        config = json.loads(content)
        outbounds = config.get('outbounds', [])
        
        for outbound in outbounds:
            tag = outbound.get('tag', '')
            settings = outbound.get('settings', {})
            vnext = settings.get('vnext', [{}])[0]
            address = vnext.get('address', '')
            
            stream_settings = outbound.get('streamSettings', {})
            reality_settings = stream_settings.get('realitySettings', {})
            
            if reality_settings and address:
                REALITY_DATABASE[address] = {
                    'publicKey': reality_settings.get('publicKey', ''),
                    'shortId': reality_settings.get('shortId', ''),
                    'serverName': reality_settings.get('serverName', address),
                    'fingerprint': reality_settings.get('fingerprint', 'chrome'),
                    'spiderX': reality_settings.get('spiderX', '')
                }
                print(f"  🔑 Загружены Reality параметры для {address} (tag: {tag})")
    
    except Exception as e:
        print(f"  ⚠️  Ошибка загрузки Reality базы: {e}")

def process_simple_vless_config(config_obj, idx):
    """Обрабатывает упрощенный формат конфигурации VLESS"""
    
    address = config_obj.get('serverAddress', '')
    port = config_obj.get('serverPort', 443)
    user_id = config_obj.get('uuid', '')
    name = config_obj.get('name', f'proxy-{idx+1}')
    
    if not address or not user_id:
        print(f"  ✗ Пропущена конфигурация: отсутствует address или uuid")
        return None, None
    
    # Определяем flow из поля encryption (неправильное название в исходном JSON)
    flow = config_obj.get('encryption', '')
    if flow and 'xtls' not in flow.lower() and 'vision' not in flow.lower():
        flow = ''  # Если это не flow, игнорируем
    
    network = config_obj.get('type', 'tcp')
    
    # Проверяем Reality параметры в самом конфиге
    pbk = config_obj.get('realityPubKey', '').strip()
    sid = config_obj.get('realityShortId', '').strip()
    sni = config_obj.get('sni', '').strip()
    fp = config_obj.get('utlsFingerprint', '').strip()
    
    # Если параметры пустые, ищем в базе данных по адресу
    if not pbk or not sid:
        if address in REALITY_DATABASE:
            reality_data = REALITY_DATABASE[address]
            pbk = reality_data['publicKey']
            sid = reality_data['shortId']
            if not sni:
                sni = reality_data['serverName']
            if not fp:
                fp = reality_data['fingerprint']
            print(f"  ℹ️  Использованы Reality параметры из базы для {address}")
        else:
            print(f"  ⚠️  Reality параметры не найдены для {address}")
            # Пробуем найти по похожему домену
            for db_address, reality_data in REALITY_DATABASE.items():
                if address in db_address or db_address in address:
                    pbk = reality_data['publicKey']
                    sid = reality_data['shortId']
                    if not sni:
                        sni = reality_data['serverName']
                    if not fp:
                        fp = reality_data['fingerprint']
                    print(f"  ℹ️  Найдены похожие Reality параметры от {db_address}")
                    break
    
    # Если всё ещё нет параметров, это ошибка
    if not pbk:
        print(f"  ✗ КРИТИЧЕСКАЯ ОШИБКА: publicKey не найден для {address}")
        print(f"     Добавьте сервер в configs2.txt или укажите параметры вручную")
        return None, None
    
    # Определяем security
    if pbk or sid:
        security = 'reality'
    else:
        security = config_obj.get('security', 'none')
    
    if not sni and security == 'reality':
        sni = address  # Используем адрес сервера как SNI
    
    if not fp or fp == '':
        fp = 'chrome'
    
    # Создаем outbound
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
                            "encryption": "none"  # VLESS всегда использует "none"
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
        # Добавляем sockopt для xtls-rprx-vision
        if "vision" in flow.lower():
            new_outbound["streamSettings"]["sockopt"] = {
                "tcpNoDelay": True,
                "tcpKeepAliveIdle": 100,
                "mark": 255
            }
    
    # Базовые параметры для ссылки
    params = {
        'type': network,
        'encryption': 'none',  # VLESS encryption всегда none
        'security': security
    }
    
    if flow:
        params['flow'] = flow
    
    # Reality настройки
    if security == 'reality':
        new_outbound["streamSettings"]["security"] = "reality"
        
        reality_settings = {
            "show": False
        }
        
        if sni:
            params['sni'] = sni
            reality_settings['serverName'] = sni
            
        params['fp'] = fp
        reality_settings['fingerprint'] = fp
        
        if pbk:
            params['pbk'] = pbk
            reality_settings['publicKey'] = pbk
            
        if sid:
            params['sid'] = sid
            reality_settings['shortId'] = sid
        
        # Проверяем spiderX в базе
        if address in REALITY_DATABASE and REALITY_DATABASE[address].get('spiderX'):
            spiderX = REALITY_DATABASE[address]['spiderX']
            params['spx'] = spiderX
            reality_settings['spiderX'] = spiderX
        
        new_outbound["streamSettings"]["realitySettings"] = reality_settings
    
    # TLS настройки
    elif security == 'tls':
        params['security'] = 'tls'
        new_outbound["streamSettings"]["security"] = "tls"
        
        tls_config = {
            "allowInsecure": config_obj.get('allowInsecure', False),
            "show": False
        }
        
        if sni:
            params['sni'] = sni
            tls_config['serverName'] = sni
            
        params['fp'] = fp
        tls_config['fingerprint'] = fp
        
        alpn = config_obj.get('alpn', '')
        if alpn:
            alpn_list = [a.strip() for a in alpn.split(',') if a.strip()]
            if alpn_list:
                params['alpn'] = ','.join(alpn_list)
                tls_config['alpn'] = alpn_list
        
        new_outbound["streamSettings"]["tlsSettings"] = tls_config
    
    # WebSocket настройки
    if network == 'ws':
        ws_config = {}
        
        host = config_obj.get('host', '')
        if host:
            params['host'] = host
            ws_config['headers'] = {"Host": host}
            
        path = config_obj.get('path', '/')
        if path:
            params['path'] = path
            ws_config['path'] = path
        
        max_early_data = config_obj.get('wsMaxEarlyData', 0)
        if max_early_data > 0:
            ws_config['maxEarlyData'] = max_early_data
        
        early_data_header = config_obj.get('earlyDataHeaderName', '')
        if early_data_header:
            ws_config['earlyDataHeaderName'] = early_data_header
        
        new_outbound["streamSettings"]["wsSettings"] = ws_config
    
    # gRPC настройки
    elif network == 'grpc':
        grpc_config = {}
        
        service_name = config_obj.get('path', '')
        if service_name:
            params['serviceName'] = service_name
            grpc_config['serviceName'] = service_name
        
        new_outbound["streamSettings"]["grpcSettings"] = grpc_config
    
    # HTTP/2 настройки
    elif network == 'h2' or network == 'http':
        h2_config = {}
        
        host = config_obj.get('host', '')
        if host:
            host_list = [h.strip() for h in host.split(',') if h.strip()]
            if host_list:
                params['host'] = ','.join(host_list)
                h2_config['host'] = host_list
            
        path = config_obj.get('path', '/')
        if path:
            params['path'] = path
            h2_config['path'] = path
        
        new_outbound["streamSettings"]["httpSettings"] = h2_config
    
    # TCP настройки
    elif network == 'tcp':
        tcp_config = {
            "header": {
                "type": "none"
            }
        }
        new_outbound["streamSettings"]["tcpSettings"] = tcp_config
    
    # Формируем query string для ссылки
    query = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    
    # Формируем имя (убираем лишние пробелы)
    name_clean = name.strip()
    name_encoded = urllib.parse.quote(name_clean)
    
    # Собираем ссылку
    vless_link = f"vless://{user_id}@{address}:{port}?{query}#{name_encoded}"
    
    # Создаем полную конфигурацию
    full_config = create_v2ray_config(new_outbound, name_clean)
    
    return vless_link, full_config

def process_outbound(outbound, remark, idx):
    """Обрабатывает один outbound из полного формата V2Ray конфига"""
    
    protocol = outbound.get('protocol', '')
    
    # Пропускаем не-VLESS протоколы
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
        # Добавляем sockopt для xtls-rprx-vision
        if "vision" in flow.lower():
            new_outbound["streamSettings"]["sockopt"] = {
                "tcpNoDelay": True,
                "tcpKeepAliveIdle": 100,
                "mark": 255
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
        
        reality_settings = {"show": False}
        
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
        
        params['security'] = 'reality'
        new_outbound["streamSettings"]["realitySettings"] = reality_settings
    
    # TLS настройки
    elif security == 'tls':
        params['security'] = 'tls'
        tls_settings = stream_settings.get('tlsSettings', {})
        
        new_outbound["streamSettings"]["security"] = "tls"
        tls_config = {"show": False}
        
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
        
        allow_insecure = tls_settings.get('allowInsecure', False)
        tls_config['allowInsecure'] = allow_insecure
        
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
    
    # TCP настройки
    elif network == 'tcp':
        tcp_settings = stream_settings.get('tcpSettings', {})
        if tcp_settings:
            new_outbound["streamSettings"]["tcpSettings"] = tcp_settings
        else:
            new_outbound["streamSettings"]["tcpSettings"] = {
                "header": {"type": "none"}
            }
    
    # Формируем query string для ссылки
    query = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    
    # Формируем имя
    tag = outbound.get('tag', f'proxy-{idx+1}')
    name = f"{remark} - {tag}"
    name_encoded = urllib.parse.quote(name)
    
    # Собираем ссылку
    vless_link = f"vless://{user_id}@{address}:{port}?{query}#{name_encoded}"
    
    # Создаем полную конфигурацию
    full_config = create_v2ray_config(new_outbound, name)
    
    return vless_link, full_config

def detect_config_format(config_data):
    """Определяет формат конфигурации"""
    try:
        config = json.loads(config_data)
        
        # Проверяем наличие ключевых полей для упрощенного формата
        if 'serverAddress' in config and 'serverPort' in config and 'uuid' in config:
            return 'simple'
        
        # Проверяем наличие outbounds для полного формата
        if 'outbounds' in config:
            return 'full'
        
        return 'unknown'
    except:
        return 'unknown'

def json_to_vless(config_data, source_name="Proxy"):
    """Конвертирует JSON конфигурацию V2Ray в VLESS ссылки и конфиги"""
    
    vless_links = []
    json_configs = []
    
    try:
        config = json.loads(config_data)
        format_type = detect_config_format(config_data)
        
        if format_type == 'simple':
            # Обрабатываем упрощенный формат
            name = config.get('name', source_name)
            link, json_config = process_simple_vless_config(config, 0)
            
            if link and json_config:
                vless_links.append(link)
                json_configs.append(json_config)
                
                address = config.get('serverAddress', 'unknown')
                port = config.get('serverPort', '?')
                print(f"  ✓ Создана конфигурация: {name} ({address}:{port})")
        
        elif format_type == 'full':
            # Обрабатываем полный формат с outbounds
            remark = config.get('remarks', source_name)
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
        else:
            print(f"  ⚠️  Неизвестный формат конфигурации")
    
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
        return 0, []
    
    print(f"\n📄 Размер файла: {len(content)} символов")
    
    # Разделяем на отдельные JSON объекты
    configs = split_json_configs(content)
    
    print(f"📦 Найдено {len(configs)} JSON конфигураций\n")
    
    # Конвертируем все конфигурации
    all_links = []
    all_json_configs = []
    
    for i, config in enumerate(configs, 1):
        print(f"Обработка конфигурации {i}/{len(configs)}...")
        links, json_configs = json_to_vless(config, source_name)
        all_links.extend(links)
        all_json_configs.extend(json_configs)
    
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
            # Декодируем имя для читаемости
            try:
                link_parts = link.split('#')
                if len(link_parts) == 2:
                    decoded_name = urllib.parse.unquote(link_parts[1])
                    print(f"{i}. {link_parts[0][:70]}...#{decoded_name}")
                else:
                    print(f"{i}. {link[:100]}...")
            except:
                print(f"{i}. {link[:100]}...")
    else:
        print(f"\n❌ Не удалось сгенерировать ни одной ссылки из {filename}!")
        print("Проверьте формат конфигураций в файле")
    
    return len(all_links), all_json_configs

def main():
    print("=" * 60)
    print("V2Ray Multi-Config Converter v2.1")
    print("=" * 60)
    
    # Сначала загружаем Reality базу из configs2.txt
    print("\n🔐 Загрузка Reality параметров из configs2.txt...")
    load_reality_database('configs2.txt')
    
    total_links = 0
    all_json_configs = []
    
    # Обработка configs.txt → output.txt
    count1, configs1 = process_config_file('configs.txt', 'output.txt', 'Config1')
    total_links += count1
    all_json_configs.extend(configs1)
    
    # Обработка configs2.txt → output2.txt
    count2, configs2 = process_config_file('configs2.txt', 'output2.txt', 'Config2')
    total_links += count2
    all_json_configs.extend(configs2)
    
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

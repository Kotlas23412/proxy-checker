#!/usr/bin/env python3
import json
import urllib.parse

def json_to_vless(config_data):
    """Конвертирует JSON конфигурацию V2Ray в VLESS ссылку"""
    
    vless_links = []
    
    try:
        config = json.loads(config_data)
        
        # Получаем remarks для имени конфигурации
        remark = config.get('remarks', 'Proxy')
        
        # Обрабатываем все outbounds
        outbounds = config.get('outbounds', [])
        
        for idx, outbound in enumerate(outbounds):
            protocol = outbound.get('protocol', '')
            
            # Пропускаем не-VLESS протоколы
            if protocol != 'vless':
                continue
                
            settings = outbound.get('settings', {})
            vnext_list = settings.get('vnext', [])
            
            if not vnext_list:
                continue
                
            for vnext in vnext_list:
                address = vnext.get('address', '')
                port = vnext.get('port', 443)
                
                users = vnext.get('users', [])
                if not users:
                    continue
                    
                user = users[0]
                user_id = user.get('id', '')
                encryption = user.get('encryption', 'none')
                flow = user.get('flow', '')
                
                stream_settings = outbound.get('streamSettings', {})
                network = stream_settings.get('network', 'tcp')
                security = stream_settings.get('security', 'none')
                
                # Базовые параметры
                params = {
                    'type': network,
                    'encryption': encryption,
                }
                
                # Добавляем flow если есть
                if flow:
                    params['flow'] = flow
                
                # Reality настройки
                if security == 'reality':
                    reality = stream_settings.get('realitySettings', {})
                    params['security'] = 'reality'
                    
                    sni = reality.get('serverName', '')
                    if sni:
                        params['sni'] = sni
                        
                    fp = reality.get('fingerprint', '')
                    if fp:
                        params['fp'] = fp
                        
                    pbk = reality.get('publicKey', '')
                    if pbk:
                        params['pbk'] = pbk
                        
                    sid = reality.get('shortId', '')
                    if sid:
                        params['sid'] = sid
                
                # TLS настройки
                elif security == 'tls':
                    params['security'] = 'tls'
                    tls_settings = stream_settings.get('tlsSettings', {})
                    
                    sni = tls_settings.get('serverName', '')
                    if sni:
                        params['sni'] = sni
                        
                    fp = tls_settings.get('fingerprint', 'chrome')
                    if fp:
                        params['fp'] = fp
                        
                    alpn = tls_settings.get('alpn', [])
                    if alpn:
                        params['alpn'] = ','.join(alpn)
                
                # WebSocket настройки
                if network == 'ws':
                    ws_settings = stream_settings.get('wsSettings', {})
                    host = ws_settings.get('headers', {}).get('Host', '')
                    if host:
                        params['host'] = host
                    path = ws_settings.get('path', '/')
                    if path:
                        params['path'] = path
                
                # XHTTP настройки
                elif network == 'xhttp':
                    xhttp_settings = stream_settings.get('xhttpSettings', {})
                    host = xhttp_settings.get('host', '')
                    if host:
                        params['host'] = host
                    path = xhttp_settings.get('path', '/')
                    if path:
                        params['path'] = path
                    mode = xhttp_settings.get('mode', 'auto')
                    if mode:
                        params['mode'] = mode
                
                # Формируем query string
                query = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
                
                # Формируем имя
                tag = outbound.get('tag', f'proxy-{idx+1}')
                name = f"{remark} - {tag}"
                name_encoded = urllib.parse.quote(name)
                
                # Собираем ссылку
                vless_link = f"vless://{user_id}@{address}:{port}/?{query}#{name_encoded}"
                vless_links.append(vless_link)
                
                print(f"  ✓ Создана ссылка для {tag}: {address}:{port}")
    
    except json.JSONDecodeError as e:
        print(f"  ✗ Ошибка парсинга JSON: {e}")
    except Exception as e:
        print(f"  ✗ Ошибка: {e}")
    
    return vless_links

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

def main():
    print("=" * 60)
    print("V2Ray Config to VLESS Link Converter")
    print("=" * 60)
    
    # Читаем файл с конфигурациями
    try:
        with open('configs.txt', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print("❌ Файл configs.txt не найден!")
        return
    
    print(f"\n📄 Размер файла: {len(content)} символов")
    
    # Разделяем на отдельные JSON объекты
    configs = split_json_configs(content)
    
    print(f"📦 Найдено {len(configs)} JSON конфигураций\n")
    
    # Конвертируем все конфигурации
    all_links = []
    
    for i, config in enumerate(configs, 1):
        print(f"Обработка конфигурации {i}/{len(configs)}...")
        links = json_to_vless(config)
        all_links.extend(links)
    
    # Записываем результат
    if all_links:
        with open('output.txt', 'w', encoding='utf-8') as f:
            for link in all_links:
                f.write(link + '\n')
        
        print(f"\n{'=' * 60}")
        print(f"✅ Успешно сгенерировано {len(all_links)} VLESS ссылок")
        print(f"📝 Результат сохранен в output.txt")
        print(f"{'=' * 60}")
        
        print("\n🔗 Первые 5 ссылок:")
        for i, link in enumerate(all_links[:5], 1):
            print(f"{i}. {link[:100]}...")
    else:
        print("\n❌ Не удалось сгенерировать ни одной ссылки!")
        print("Проверьте формат конфигураций в configs.txt")

if __name__ == '__main__':
    main()

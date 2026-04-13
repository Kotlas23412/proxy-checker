#!/usr/bin/env python3
import json
import base64
import urllib.parse

def json_to_vless(config_data):
    """Конвертирует JSON конфигурацию V2Ray в VLESS ссылку"""
    
    vless_links = []
    
    try:
        config = json.loads(config_data)
        
        # Получаем remarks для имени конфигурации
        remark = config.get('remarks', 'Proxy')
        
        # Обрабатываем все outbounds
        for idx, outbound in enumerate(config.get('outbounds', [])):
            if outbound.get('protocol') != 'vless':
                continue
                
            settings = outbound.get('settings', {})
            vnext_list = settings.get('vnext', [])
            
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
                
                # Параметры
                params = {
                    'type': network,
                    'encryption': encryption,
                    'flow': flow
                }
                
                # Reality настройки
                if security == 'reality':
                    reality = stream_settings.get('realitySettings', {})
                    params['sni'] = reality.get('serverName', '')
                    params['fp'] = reality.get('fingerprint', '')
                    params['security'] = 'reality'
                    params['pbk'] = reality.get('publicKey', '')
                    params['sid'] = reality.get('shortId', '')
                
                # TLS настройки
                elif security == 'tls':
                    params['security'] = 'tls'
                    params['sni'] = stream_settings.get('tlsSettings', {}).get('serverName', '')
                    params['fp'] = stream_settings.get('tlsSettings', {}).get('fingerprint', 'chrome')
                    alpn = stream_settings.get('tlsSettings', {}).get('alpn', [])
                    if alpn:
                        params['alpn'] = ','.join(alpn)
                
                # WebSocket настройки
                if network == 'ws':
                    ws_settings = stream_settings.get('wsSettings', {})
                    params['host'] = ws_settings.get('headers', {}).get('Host', '')
                    params['path'] = ws_settings.get('path', '/')
                
                # TCP настройки
                if network == 'tcp':
                    tcp_settings = stream_settings.get('tcpSettings', {})
                
                # Удаляем пустые параметры
                params = {k: v for k, v in params.items() if v}
                
                # Формируем query string
                query = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
                
                # Формируем имя
                tag = outbound.get('tag', f'proxy-{idx+1}')
                name = f"{remark} - {tag}"
                name_encoded = urllib.parse.quote(name)
                
                # Собираем ссылку
                vless_link = f"vless://{user_id}@{address}:{port}/?{query}#{name_encoded}"
                vless_links.append(vless_link)
    
    except json.JSONDecodeError as e:
        print(f"Ошибка парсинга JSON: {e}")
    except Exception as e:
        print(f"Ошибка: {e}")
    
    return vless_links

def main():
    # Читаем файл с конфигурациями
    with open('configs.txt', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Разделяем на отдельные JSON объекты
    configs = []
    current_config = ""
    brace_count = 0
    
    for line in content.split('\n'):
        if line.strip():
            current_config += line + '\n'
            brace_count += line.count('{') - line.count('}')
            
            if brace_count == 0 and current_config.strip():
                configs.append(current_config.strip())
                current_config = ""
    
    # Конвертируем все конфигурации
    all_links = []
    for config in configs:
        links = json_to_vless(config)
        all_links.extend(links)
    
    # Записываем результат
    with open('output.txt', 'w', encoding='utf-8') as f:
        for link in all_links:
            f.write(link + '\n')
    
    print(f"Сгенерировано {len(all_links)} VLESS ссылок")
    print("\nПример ссылок:")
    for link in all_links[:3]:
        print(link)

if __name__ == '__main__':
    main()

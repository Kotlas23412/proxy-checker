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
    
    # Добавляем meta каждому профилю. Страну сначала определяем по флагу,
    # чтобы, например, "🇩🇪 Обход БС" получил описание "Германия".
    country_by_flag = {
        "🇫🇮": "Финляндия",
        "🇨🇿": "Чехия",
        "🇩🇪": "Германия",
        "🇳🇱": "Нидерланды",
        "🇫🇷": "Франция",
        "🇸🇪": "Швеция",
        "🇨🇭": "Швейцария",
        "🇵🇱": "Польша",
        "🇪🇪": "Эстония",
        "🇱🇻": "Латвия",
        "🇱🇹": "Литва",
        "🇬🇧": "Великобритания",
        "🇺🇸": "США",
        "🇨🇦": "Канада",
        "🇯🇵": "Япония",
        "🇸🇬": "Сингапур",
        "🇹🇷": "Турция",
        "🇷🇺": "Россия",
        "🇦🇹": "Австрия",
        "🇧🇪": "Бельгия",
        "🇮🇹": "Италия",
        "🇪🇸": "Испания",
        "🇳🇴": "Норвегия",
        "🇩🇰": "Дания",
        "🇮🇪": "Ирландия",
        "🇷🇴": "Румыния",
        "🇧🇬": "Болгария",
        "🇭🇺": "Венгрия",
        "🇸🇰": "Словакия",
        "🇸🇮": "Словения",
        "🇭🇷": "Хорватия",
        "🇬🇷": "Греция",
        "🇵🇹": "Португалия",
        "🇮🇸": "Исландия",
        "🇱🇺": "Люксембург",
        "🇺🇦": "Украина",
        "🇰🇷": "Южная Корея",
        "🇮🇳": "Индия",
        "🇧🇷": "Бразилия",
        "🇦🇺": "Австралия",
    }
    country = next(
        (name for flag, name in country_by_flag.items() if flag in remark),
        None,
    )

    # Если флага нет, используем название профиля как запасной вариант.
    if not country:
        country = re.sub(r"^[^\wА-Яа-я]+", "", remark).strip() or remark.strip() or "Неизвестная страна"
        if "обход бс" in country.casefold():
            country = "Неизвестная страна"

    config["meta"] = {"serverDescription": country}

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
    

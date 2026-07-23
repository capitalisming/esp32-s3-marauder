# ESP32-S3 Marauder

Wi-Fi security testing tool for **ESP32-S3-WROOM-1** (N16R8), inspired by [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder).

> **⚠️ LEGAL DISCLAIMER**
>
> This tool is designed for **authorized penetration testing** and **educational purposes only**.
> Using it against networks you do not own or have explicit written permission to test is **illegal**.
> **You are solely responsible for your actions.**

---

## ⚡ Features

| Feature | Description |
|---------|-------------|
| **Wi-Fi Scanner** | Scan APs (SSID, BSSID, channel, RSSI, encryption) |
| **Client Scanner** | Discover connected clients via promiscuous mode with strict AP filtering |
| **Deauthentication** | Send 802.11 deauth/disassoc frames (single client or broadcast) |
| **Handshake Capture** | Capture WPA 4-way EAPOL handshake, export to HC22000 + PCAP |
| **Evil Twin** | Clone AP + DNS spoofing + HTTP captive portal + credential harvesting |
| **Serial CLI** | Interactive menu over USB serial (115200 baud) |
| **SD Card Support** | Store captures on microSD card for offline processing |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────┐
│                    main.py (CLI)                │
├──────────┬──────────┬──────────┬────────────────┤
│ scanner  │ deauther │handshake │   evil_twin    │
│          │          │          │ ┌────────────┐ │
│          │          │          │ │  captive   │ │
│          │          │          │ │  portal    │ │
│          │          │          │ └────────────┘ │
├──────────┴──────────┴──────────┴────────────────┤
│         packet_builder  /  utils                │
├─────────────────────────────────────────────────┤
│           _wifi_raw (C module)                  │
├─────────────────────────────────────────────────┤
│         ESP-IDF  Wi-Fi Driver                   │
│      (promiscuous mode + 80211_tx)              │
└─────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
esp32_marauder/
├── c_module/
│   ├── wifi_raw/
│   │   ├── wifi_raw.c            # C module: promiscuous ring buffer + raw TX
│   │   ├── micropython.mk        # Make build config
│   │   └── micropython.cmake     # CMake build config
│   └── BUILD_INSTRUCTIONS.md     # Firmware build guide (RU)
├── src/
│   ├── boot.py                   # Device startup
│   ├── main.py                   # CLI menu entry point
│   ├── scanner.py                # AP + client scanner
│   ├── deauther.py               # Deauthentication attack
│   ├── handshake.py              # EAPOL handshake capture
│   ├── evil_twin.py              # Evil Twin orchestrator
│   ├── captive_portal.py         # HTTP + DNS server
│   ├── portal_page.html          # Captive portal login page
│   ├── packet_builder.py         # 802.11 frame builder/parser
│   └── utils.py                  # Shared utilities
└── README.md
```

---

## 📖 Подробная шпаргалка по меню CLI

Управление осуществляется через последовательный порт (Serial, 115200 baud).  
Введите цифру нужного пункта и следуйте подсказкам на экране.

### 1. Сканирование точек доступа (`[1] Scan Wi-Fi Networks`)
* **Вход**: Введите `1` -> нажмите `Enter`.
* **Запрос**: `Scan timeout (seconds) [10]:` — время сканирования в секундах (по умолчанию 10 сек).
* **Результат**: Выводится таблица всех найденных роутеров с номерами `#`, SSID, BSSID (MAC), каналом (CH), уровнем сигнала (RSSI) и типом шифрования (WPA2 и т.д.).

---

### 2. Сканирование клиентов (`[2] Scan Clients`)
* **Вход**: Введите `2` -> нажмите `Enter`.
* **Запрос**: `Filter by selected AP? [Y/n]:`
  * `y` (или Enter) — искать клиентов **только** для ранее выбранного роутера.
  * `n` — искать **все** активные устройства в эфире вокруг.
* **Запрос**: `Scan timeout (seconds) [15]:` — время сканирования (например `15`).
* **Результат**: Таблица всех активных устройств (смартфонов/ноутбуков): их MAC-адреса, BSSID роутера и уровень сигнала RSSI.

---

### 3. Выбор целевого роутера (`[3] Select Target AP`)
* **Вход**: Введите `3` -> нажмите `Enter`.
* **Предусловие**: Сначала вызовите сканирование сетей (пункт `1`).
* **Запрос**: `Select AP # :` — введите номер `#` из таблицы (например `0`).
* **Результат**: Роутер сохранится как цель в главном меню (`Target AP:`).

---

### 4. Выбор целевого клиента (`[4] Select Target Client`)
* **Вход**: Введите `4` -> нажмите `Enter`.
* **Предусловие**: Сначала вызовите сканирование клиентов (пункт `2`).
* **Запрос**: `Select Client # :` — введите номер `#` из таблицы клиентов.
* **Результат**: Клиент сохранится как цель в главном меню (`Target Client:`).

---

### 5. Deauth-атака (`[5] Deauth Attack`)
* **Предусловие**: Выберите целевой роутер (пункт `3`).
* **Вход**: Введите `5` -> нажмите `Enter`.
* **Выбор режима `Mode:`**:
  * **`1` (Точечное отключение 1 клиента)**:
    1. Введите `1`.
    2. Выберите клиента (или введите его MAC).
    3. `Number of rounds [100]:` — кол-во циклов (например `20` или `500`).
    4. `Delay between rounds (ms) [100]:` — задержка в мс (например `20`).
  * **`2` (Массовый Deauth всех клиентов роутера)**:
    1. Введите `2`.
    2. `Number of rounds [100]:` — например `20`.
    3. `Delay between rounds (ms) [100]:` — например `20`.

---

### 6. Захват WPA Handshake (`[6] Capture Handshake`)
* **Предусловие**: Выберите целевой роутер (пункт `3`).
* **Вход**: Введите `6` -> нажмите `Enter`.
* **Запрос**: `Auto-deauth to force reconnection? [Y/n]:`
  * `n` — **(Рекомендуется)** Без авто-деаута. Вы просто вручную выключаете и включаете Wi-Fi на своем смартфоне.
  * `y` — С авто-деаутом от платы.
* **Процесс**: Ждёт перехвата кадра (`M1 M2`).
* **Результат**: При успешном перехвате выведет `*** HANDSHAKE COMPLETE: M1 M2 __ __ ***`.
* **Экспорт**: Позволяет сохранить результат в формате `.hc22000` (для Hashcat) и `.pcap` (для Wireshark).

---

### 7. Evil Twin + Captive Portal (`[7] Evil Twin + Captive Portal`)
* **Вход**: Введите `7` -> нажмите `Enter`.
* **Запрос**: `Deauth original AP clients? [Y/n]:`
  * `n` — создать фейковую сеть без глушения оригинала.
  * `y` — параллельно глушить оригинальный роутер, заставляя клиентов переподключаться к поддельной сети.
* **Работа**: ESP32 поднимет фейковую AP, запустит DNS-спуфинг и HTTP Captive Portal.
* **Результат**: При вводе пароля клиентом на странице входа, пароль мгновенно отображается в консоли `PASSWORD CAPTURED:` и сохраняется на устройство.

---

### 8. Просмотр перехваченных данных (`[8] View Captured Data`)
Отображает список всех перехваченных паролей с портала и созданных файлов дампов.

### 9. Настройки и системная инфо (`[9] Settings & Info`)
Показывает объем свободной оперативной памяти RAM, состояние флеш-памяти и SD-карты.

---

## 🛠 Быстрый старт (Загрузка скриптов через PowerShell)

```powershell
cd esp32_marauder

python -m mpremote connect auto fs cp src/boot.py :boot.py + fs cp src/main.py :main.py + fs cp src/utils.py :utils.py + fs cp src/packet_builder.py :packet_builder.py + fs cp src/scanner.py :scanner.py + fs cp src/deauther.py :deauther.py + fs cp src/handshake.py :handshake.py + fs cp src/evil_twin.py :evil_twin.py + fs cp src/captive_portal.py :captive_portal.py + fs cp src/portal_page.html :portal_page.html + reset
```

Подключение к консоли управления:
```powershell
python -m mpremote connect auto
```

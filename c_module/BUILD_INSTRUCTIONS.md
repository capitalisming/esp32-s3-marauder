# Сборка кастомной прошивки MicroPython с модулем `_wifi_raw`

Данная инструкция описывает сборку MicroPython для **ESP32-S3** с
включённым C-модулем `_wifi_raw`, который предоставляет доступ к
promiscuous mode и инжекции сырых 802.11 фреймов.

> **⚠️ Предупреждение**: Рекомендуется выполнять сборку в Linux или macOS.
> На Windows используйте WSL 2 (Ubuntu).

---

## 1. Предварительные требования

| Компонент       | Версия          |
|-----------------|-----------------|
| Python          | 3.8+            |
| Git             | 2.x+            |
| ESP-IDF         | v5.0.x — v5.2.x |
| CMake           | 3.16+           |
| Ninja           | 1.10+           |

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y git wget flex bison gperf python3 python3-pip \
    python3-venv cmake ninja-build ccache libffi-dev libssl-dev \
    dfu-util libusb-1.0-0
```

---

## 2. Установка ESP-IDF

```bash
mkdir -p ~/esp && cd ~/esp

# Клонируем ESP-IDF (ветка v5.2.x рекомендуется)
git clone -b v5.2.2 --recursive \
    https://github.com/espressif/esp-idf.git

cd esp-idf
./install.sh esp32s3

# Активируем окружение (выполнять в каждом новом терминале)
. ./export.sh
```

---

## 3. Клонирование MicroPython

```bash
cd ~/
git clone https://github.com/micropython/micropython.git
cd micropython

# Инициализация подмодулей
git submodule update --init --recursive

# Сборка mpy-cross (кросс-компилятор .mpy)
make -C mpy-cross
```

---

## 4. Размещение C-модуля

Скопируйте директорию `wifi_raw/` в удобное место, например:

```bash
# Предположим, что проект находится в ~/esp32_marauder
cp -r ~/esp32_marauder/c_module/wifi_raw ~/micropython/ports/esp32/user_modules/wifi_raw
```

Или используйте абсолютный путь при сборке (см. шаг 5).

---

## 5. Сборка прошивки

```bash
cd ~/micropython/ports/esp32

# Вариант A: модуль внутри дерева MicroPython
make submodules
make BOARD=ESP32_GENERIC_S3 \
     USER_C_MODULES=~/micropython/ports/esp32/user_modules/wifi_raw/micropython.cmake

# Вариант B: модуль по абсолютному пути (без копирования)
make BOARD=ESP32_GENERIC_S3 \
     USER_C_MODULES=/absolute/path/to/esp32_marauder/c_module/wifi_raw/micropython.cmake
```

> **Примечание**: Если у вас ESP32-S3 с PSRAM (например, N16R8),
> может потребоваться указать `BOARD_VARIANT`:
> ```bash
> make BOARD=ESP32_GENERIC_S3 BOARD_VARIANT=SPIRAM_OCT \
>      USER_C_MODULES=.../wifi_raw/micropython.cmake
> ```

Результат сборки: `build-ESP32_GENERIC_S3/firmware.bin`

---

## 6. Прошивка ESP32-S3

```bash
# Полная очистка flash (рекомендуется при первой прошивке)
esptool.py --chip esp32s3 --port /dev/ttyUSB0 erase_flash

# Прошивка
esptool.py --chip esp32s3 --port /dev/ttyUSB0 \
    --baud 460800 write_flash -z 0x0 \
    build-ESP32_GENERIC_S3/firmware.bin
```

> На Windows порт будет `COM3` (или другой — проверьте в Диспетчере устройств).
> На macOS: `/dev/cu.usbserial-*` или `/dev/cu.SLAB_USBtoUART`.

---

## 7. Загрузка Python-скриптов

Используйте `mpremote` для загрузки скриптов на устройство:

```bash
pip install mpremote

# Загрузка всех файлов из src/
cd ~/esp32_marauder
mpremote connect /dev/ttyUSB0 cp src/boot.py :boot.py
mpremote connect /dev/ttyUSB0 cp src/main.py :main.py
mpremote connect /dev/ttyUSB0 cp src/utils.py :utils.py
mpremote connect /dev/ttyUSB0 cp src/packet_builder.py :packet_builder.py
mpremote connect /dev/ttyUSB0 cp src/scanner.py :scanner.py
mpremote connect /dev/ttyUSB0 cp src/deauther.py :deauther.py
mpremote connect /dev/ttyUSB0 cp src/handshake.py :handshake.py
mpremote connect /dev/ttyUSB0 cp src/evil_twin.py :evil_twin.py
mpremote connect /dev/ttyUSB0 cp src/captive_portal.py :captive_portal.py
mpremote connect /dev/ttyUSB0 cp src/portal_page.html :portal_page.html

# Перезагрузка
mpremote connect /dev/ttyUSB0 reset
```

---

## 8. Проверка модуля

Подключитесь к REPL (через Serial, 115200 бод):

```python
>>> import _wifi_raw
>>> _wifi_raw.init()
>>> _wifi_raw.set_channel(6)
>>> _wifi_raw.get_channel()
6
>>> _wifi_raw.promiscuous_start(lambda buf, t, rssi: print(len(buf)), 0x01)
# Должны появиться числа — размеры перехваченных management-фреймов
>>> _wifi_raw.promiscuous_stop()
```

---

## Возможные проблемы

| Проблема | Решение |
|----------|---------|
| `ImportError: no module named '_wifi_raw'` | Модуль не был включён в сборку. Проверьте путь `USER_C_MODULES`. |
| `esp_wifi_80211_tx` возвращает ошибку | WiFi должен быть инициализирован (`init()`). Некоторые фреймы могут блокироваться без STA-режима — попробуйте `WIFI_MODE_STA` вместо `NULL`. |
| Сборка падает на `ring_mux` | Убедитесь что используется ESP-IDF v5.x (в v4.x API спинлоков отличается). |
| Пакеты теряются (ring full) | Увеличьте `RING_SIZE` в `wifi_raw.c` или уменьшите объём данных в callback. |

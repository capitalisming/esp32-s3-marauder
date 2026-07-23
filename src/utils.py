# utils.py — Shared utilities for ESP32-S3 Marauder
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.

import os
import gc
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

# Auth mode names (from network.WLAN.scan() authmode field)
AUTH_NAMES = {
    0: 'OPEN',
    1: 'WEP',
    2: 'WPA-PSK',
    3: 'WPA2-PSK',
    4: 'WPA/WPA2',
    5: 'WPA2-ENT',
    6: 'WPA3-PSK',
    7: 'WPA2/WPA3',
    8: 'WAPI-PSK',
}


# ---------------------------------------------------------------------------
# MAC address conversion
# ---------------------------------------------------------------------------

def mac_bytes_to_str(mac):
    """Convert 6-byte MAC to string 'AA:BB:CC:DD:EE:FF'."""
    return ':'.join('%02X' % b for b in mac)


def mac_str_to_bytes(mac_str):
    """Convert 'AA:BB:CC:DD:EE:FF' to bytes(6)."""
    parts = mac_str.replace('-', ':').split(':')
    return bytes(int(p, 16) for p in parts)


# ---------------------------------------------------------------------------
# Storage management
# ---------------------------------------------------------------------------

def get_storage_path():
    """Return base storage path: '/sd' if SD mounted, else '' (root)."""
    try:
        import boot
        if boot.SD_MOUNTED:
            return '/sd'
    except (ImportError, AttributeError):
        pass
    # Fallback: check if /sd exists
    try:
        os.stat('/sd')
        return '/sd'
    except OSError:
        pass
    return ''


def ensure_dir(path):
    """Create directory and parents if they don't exist."""
    parts = path.strip('/').split('/')
    current = ''
    for part in parts:
        current = current + '/' + part
        try:
            os.mkdir(current)
        except OSError:
            pass  # already exists or cannot create


def save_file(path, data, mode='wb'):
    """Write data to file. data can be bytes or str."""
    # Ensure parent directory exists
    parent = path.rsplit('/', 1)[0] if '/' in path else ''
    if parent:
        ensure_dir(parent)

    if isinstance(data, str) and 'b' in mode:
        data = data.encode()
    elif isinstance(data, bytes) and 'b' not in mode:
        data = data.decode()

    with open(path, mode) as f:
        f.write(data)


def append_file(path, data, mode='ab'):
    """Append data to file."""
    save_file(path, data, mode=mode)


def read_file(path, mode='rb'):
    """Read entire file content."""
    with open(path, mode) as f:
        return f.read()


def list_files(directory):
    """List files in directory. Returns list of filenames."""
    try:
        return os.listdir(directory)
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Timestamp (uptime-based, no RTC)
# ---------------------------------------------------------------------------

def timestamp():
    """Return 'HH:MM:SS' based on uptime since boot."""
    ms = time.ticks_ms()
    total_s = ms // 1000
    h = total_s // 3600
    m = (total_s % 3600) // 60
    s = total_s % 60
    return '%02d:%02d:%02d' % (h, m, s)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg, level='INFO'):
    """Print formatted log message: [HH:MM:SS] [LEVEL] msg"""
    print('[%s] [%s] %s' % (timestamp(), level, msg))


def log_error(msg):
    """Shortcut for log(msg, 'ERROR')."""
    log(msg, 'ERROR')


def log_warn(msg):
    """Shortcut for log(msg, 'WARN')."""
    log(msg, 'WARN')


# ---------------------------------------------------------------------------
# Table formatting for CLI output
# ---------------------------------------------------------------------------

def _pad_right(s, width):
    """Pad string s with spaces on the right up to width (MicroPython compat)."""
    s = str(s)
    if len(s) >= width:
        return s
    return s + ' ' * (width - len(s))


def print_table(headers, rows, col_widths=None):
    """Print formatted ASCII table to serial console.

    Args:
        headers:    list of column header strings
        rows:       list of lists (each inner list = one row)
        col_widths: optional list of int column widths;
                    if None, auto-calculated from data
    """
    if not headers:
        return

    num_cols = len(headers)

    # Auto-calculate widths if not provided
    if col_widths is None:
        col_widths = [len(str(h)) for h in headers]
        for row in rows:
            for i in range(min(len(row), num_cols)):
                w = len(str(row[i]))
                if w > col_widths[i]:
                    col_widths[i] = w
        # Add 1 char padding
        col_widths = [w + 1 for w in col_widths]

    # Separator line
    sep = '+' + '+'.join('-' * (w + 1) for w in col_widths) + '+'

    # Format one row
    def fmt_row(values):
        cells = []
        for i in range(num_cols):
            val = str(values[i]) if i < len(values) else ''
            cells.append(' ' + _pad_right(val, col_widths[i]))
        return '|' + '|'.join(cells) + '|'

    print(sep)
    print(fmt_row(headers))
    print(sep)
    for row in rows:
        print(fmt_row(row))
    if rows:
        print(sep)
    print('Total: %d entries' % len(rows))


# ---------------------------------------------------------------------------
# Channel hopping
# ---------------------------------------------------------------------------

def channel_hop_sequence():
    """Return optimized Wi-Fi channel hop order.

    Prioritises non-overlapping channels (1, 6, 11) first,
    then fills in the rest for comprehensive scanning.
    """
    return [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14, 5, 10]


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def free_mem():
    """Run garbage collection and return free memory in bytes."""
    gc.collect()
    return gc.mem_free()


def format_bytes(n):
    """Format byte count as human-readable string."""
    if n < 1024:
        return '%d B' % n
    elif n < 1024 * 1024:
        return '%.1f KB' % (n / 1024)
    else:
        return '%.1f MB' % (n / (1024 * 1024))

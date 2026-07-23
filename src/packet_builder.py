# packet_builder.py — IEEE 802.11 frame construction and parsing
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.
#
# References:
#   IEEE Std 802.11-2020, Section 9 (Frame formats)
#   https://www.ieee802.org/11/

import struct

# ---------------------------------------------------------------------------
# Frame Control field constants (2 bytes, little-endian)
# ---------------------------------------------------------------------------
# Type 0 = Management, Type 1 = Control, Type 2 = Data
#
# Frame Control: [Protocol(2)][Type(2)][Subtype(4)][Flags(8)]
#   Deauth:       0x00C0  -> Proto=0, Type=0(Mgmt), Subtype=12(Deauth)
#   Disassoc:     0x00A0  -> Proto=0, Type=0(Mgmt), Subtype=10(Disassoc)
#   Beacon:       0x0080  -> Proto=0, Type=0(Mgmt), Subtype=8(Beacon)
#   Probe Resp:   0x0050  -> Proto=0, Type=0(Mgmt), Subtype=5(ProbeResp)
#   Probe Req:    0x0040  -> Proto=0, Type=0(Mgmt), Subtype=4(ProbeReq)

FC_DEAUTH       = b'\xc0\x00'
FC_DISASSOC     = b'\xa0\x00'
FC_BEACON       = b'\x80\x00'
FC_PROBE_RESP   = b'\x50\x00'
FC_PROBE_REQ    = b'\x40\x00'

# Reason codes (IEEE 802.11-2020, Table 9-49)
REASON_UNSPECIFIED           = 1
REASON_AUTH_NO_LONGER_VALID  = 2
REASON_LEAVING               = 3
REASON_INACTIVITY            = 4
REASON_AP_FULL               = 5
REASON_CLASS2_FROM_NONAUTH   = 6
REASON_CLASS3_FROM_NONASSOC  = 7
REASON_DISASSOC_LEAVING      = 8

# Duration field (typically 0 for injected mgmt frames)
DURATION_ZERO = b'\x00\x00'

# EAPOL EtherType
EAPOL_ETHERTYPE = b'\x88\x8e'

# LLC/SNAP header indicating EAPOL
LLC_SNAP_EAPOL = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------

def _seq_ctl(seq_num):
    """Build 2-byte Sequence Control field from 12-bit sequence number."""
    # SeqCtl: [Fragment(4)][Sequence(12)] — fragment is always 0
    return struct.pack('<H', (seq_num & 0x0FFF) << 4)


def build_deauth_frame(dst_mac, src_mac, bssid,
                       reason=REASON_CLASS3_FROM_NONASSOC, seq_num=0):
    """Build IEEE 802.11 Deauthentication frame (26 bytes).

    Layout:
        Frame Control (2) + Duration (2) + DA (6) + SA (6) +
        BSSID (6) + Seq Control (2) + Reason Code (2) = 26 bytes
    """
    return (FC_DEAUTH + DURATION_ZERO +
            dst_mac + src_mac + bssid +
            _seq_ctl(seq_num) +
            struct.pack('<H', reason))


def build_disassoc_frame(dst_mac, src_mac, bssid,
                         reason=REASON_DISASSOC_LEAVING, seq_num=0):
    """Build IEEE 802.11 Disassociation frame (26 bytes).

    Same structure as Deauth but with different Frame Control.
    """
    return (FC_DISASSOC + DURATION_ZERO +
            dst_mac + src_mac + bssid +
            _seq_ctl(seq_num) +
            struct.pack('<H', reason))


def build_beacon_frame(ssid, bssid, channel, seq_num=0, interval=100):
    """Build IEEE 802.11 Beacon frame with tagged parameters.

    Args:
        ssid:      str  — network name (max 32 chars)
        bssid:     bytes(6) — BSSID / source MAC
        channel:   int  — Wi-Fi channel (1-14)
        seq_num:   int  — sequence number
        interval:  int  — beacon interval in TU (1 TU = 1024 µs)

    Returns:
        bytes — complete beacon frame
    """
    broadcast = b'\xff\xff\xff\xff\xff\xff'

    # --- MAC header (24 bytes) ---
    header = (FC_BEACON + DURATION_ZERO +
              broadcast + bssid + bssid +
              _seq_ctl(seq_num))

    # --- Fixed parameters (12 bytes) ---
    # Timestamp (8 bytes) — set to 0, AP will update
    ts = b'\x00' * 8
    # Beacon interval (2 bytes)
    bi = struct.pack('<H', interval)
    # Capability Info (2 bytes): ESS=1, Privacy=0 (open), Short Preamble=1
    cap = struct.pack('<H', 0x0421)

    fixed = ts + bi + cap

    # --- Tagged parameters ---
    tags = b''

    # Tag 0: SSID
    ssid_bytes = ssid.encode('utf-8')[:32]
    tags += b'\x00' + bytes([len(ssid_bytes)]) + ssid_bytes

    # Tag 1: Supported Rates (802.11b/g)
    rates = bytes([0x82, 0x84, 0x8B, 0x96,   # 1, 2, 5.5, 11 Mbps (basic)
                   0x0C, 0x12, 0x18, 0x24])   # 6, 9, 12, 18 Mbps
    tags += b'\x01' + bytes([len(rates)]) + rates

    # Tag 3: DS Parameter Set (channel)
    tags += b'\x03\x01' + bytes([channel & 0xFF])

    # Tag 5: TIM (Traffic Indication Map) — minimal
    tags += b'\x05\x04\x00\x01\x00\x00'

    # Tag 50: Extended Supported Rates
    ext_rates = bytes([0x30, 0x48, 0x60, 0x6C])  # 24, 36, 48, 54 Mbps
    tags += b'\x32' + bytes([len(ext_rates)]) + ext_rates

    return header + fixed + tags


# ---------------------------------------------------------------------------
# Frame parsers
# ---------------------------------------------------------------------------

def get_frame_type(packet):
    """Parse Frame Control and return (type, subtype).

    Returns:
        tuple(int, int): (type: 0=Mgmt/1=Ctrl/2=Data, subtype: 0-15)
        or None on error
    """
    if len(packet) < 2:
        return None
    fc = packet[0]
    ftype = (fc >> 2) & 0x03
    fsubtype = (fc >> 4) & 0x0F
    return (ftype, fsubtype)


def get_addresses(packet):
    """Extract (DA, SA, BSSID) from 802.11 MAC header.

    Assumes standard management/data frame layout:
        FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtl(2)

    Returns:
        tuple(bytes, bytes, bytes) — (addr1/DA, addr2/SA, addr3/BSSID)
        or None if packet is too short
    """
    if len(packet) < 24:
        return None
    addr1 = packet[4:10]
    addr2 = packet[10:16]
    addr3 = packet[16:22]
    return (addr1, addr2, addr3)


def get_ssid_from_beacon(packet):
    """Extract SSID from Beacon or Probe Response frame.

    Frame layout after MAC header (24 bytes):
        Fixed params: Timestamp(8) + Interval(2) + Capabilities(2) = 12 bytes
        Tagged params start at offset 36.

    Returns:
        str — SSID (empty string for hidden networks)
    """
    if len(packet) < 38:
        return ''

    # Tagged parameters start at byte 36
    pos = 36
    while pos + 2 <= len(packet):
        tag_id = packet[pos]
        tag_len = packet[pos + 1]
        if pos + 2 + tag_len > len(packet):
            break
        if tag_id == 0:  # SSID
            try:
                return packet[pos + 2: pos + 2 + tag_len].decode('utf-8')
            except (UnicodeError, ValueError):
                return ''
        pos += 2 + tag_len
    return ''


def get_ds_channel(packet):
    """Extract channel from DS Parameter Set tag (ID 3).

    Returns:
        int — channel number, or 0 if not found
    """
    if len(packet) < 38:
        return 0

    pos = 36
    while pos + 2 <= len(packet):
        tag_id = packet[pos]
        tag_len = packet[pos + 1]
        if pos + 2 + tag_len > len(packet):
            break
        if tag_id == 3 and tag_len >= 1:  # DS Parameter Set
            return packet[pos + 2]
        pos += 2 + tag_len
    return 0


def is_eapol(packet):
    """Check if packet contains an EAPOL frame.

    EAPOL frames are Data frames (type 2) with LLC/SNAP header
    containing EtherType 0x888E.

    On ESP32 in promiscuous mode, data frames have:
        MAC header: 24 bytes (non-QoS) or 26 bytes (QoS)
        LLC/SNAP:   AA AA 03 00 00 00 88 8E

    Returns:
        bool
    """
    if len(packet) < 34:
        return False

    ft = get_frame_type(packet)
    if ft is None or ft[0] != 2:  # must be Data frame
        return False

    # Check for QoS Data (subtype 8): has 2 extra bytes in header
    header_len = 24
    if ft[1] & 0x08:  # QoS bit set
        header_len = 26

    if len(packet) < header_len + 8:
        return False

    # Check LLC/SNAP EAPOL pattern
    llc = packet[header_len:header_len + 8]
    return llc == LLC_SNAP_EAPOL


def get_eapol_message_num(packet):
    """Determine EAPOL 4-way handshake message number (1-4).

    EAPOL-Key frame starts after LLC/SNAP header:
        LLC/SNAP (8 bytes) + EAPOL header (4 bytes) + Key Descriptor (1) +
        Key Information (2 bytes at offset +5 from EAPOL start)

    Key Information bits (big-endian uint16):
        Bit 3:  Install
        Bit 6:  ACK
        Bit 8:  MIC

    Message identification:
        M1: ACK=1, MIC=0           (AP → Client)
        M2: ACK=0, MIC=1           (Client → AP)
        M3: ACK=1, MIC=1, Install=1 (AP → Client)
        M4: ACK=0, MIC=1           (Client → AP, minimal key data)

    Returns:
        int — 1, 2, 3, or 4.  Returns 0 if cannot determine.
    """
    ft = get_frame_type(packet)
    if ft is None or ft[0] != 2:
        return 0

    header_len = 26 if (ft[1] & 0x08) else 24
    eapol_start = header_len + 8  # after LLC/SNAP

    # EAPOL header: Version(1) + Type(1) + Length(2) = 4 bytes
    # Key Descriptor Type: 1 byte
    # Key Information: 2 bytes (at eapol_start + 5)
    ki_offset = eapol_start + 5
    if len(packet) < ki_offset + 2:
        return 0

    key_info = struct.unpack('>H', packet[ki_offset:ki_offset + 2])[0]

    install = bool(key_info & (1 << 6))   # bit 6 in some references
    ack     = bool(key_info & (1 << 7))   # bit 7
    mic     = bool(key_info & (1 << 8))   # bit 8

    # Corrected bit positions per IEEE 802.11-2020:
    # Key Info is big-endian, 16 bits:
    #   B0-B2:  Key Descriptor Version
    #   B3:     Key Type (pairwise=1)
    #   B4-B5:  Reserved (in older) / Key ID
    #   B6:     Install
    #   B7:     ACK
    #   B8:     MIC (Key MIC)
    #   B9:     Secure
    #   B10:    Error
    #   B11:    Request
    #   B12:    Encrypted Key Data
    #   B13-B15: Reserved

    if ack and not mic:
        return 1        # M1: AP sends ANonce, no MIC yet
    elif not ack and mic and not install:
        # Could be M2 or M4 — differentiate by key data length
        # M2 has SNonce + key data; M4 has minimal/no key data
        kd_len_offset = eapol_start + 5 + 2 + 8 + 32 + 16 + 8 + 8
        # Simpler: check Key Data Length field
        # Key Data Length is at offset eapol_start + 5 + 2 + 16 + 32 + 16 + 8 + 8 = +97
        # That's deep; let's use a simpler heuristic:
        # EAPOL body length (from EAPOL header)
        if len(packet) >= eapol_start + 4:
            eapol_body_len = struct.unpack('>H',
                                           packet[eapol_start + 2:eapol_start + 4])[0]
            if eapol_body_len > 95 + 20:  # M2 has key data (at least RSN IE)
                return 2
            else:
                return 4
        return 2  # default guess
    elif ack and mic and install:
        return 3        # M3: AP sends ANonce + GTK, encrypted
    elif ack and mic and not install:
        return 3        # Some APs don't set Install in M3
    else:
        return 0


def parse_eapol_fields(packet):
    """Parse EAPOL-Key frame and extract fields for hashcat export.

    Returns dict with keys:
        'anonce'         — 32 bytes
        'snonce'         — 32 bytes
        'mic'            — 16 bytes
        'key_info'       — int (Key Information field)
        'replay_counter' — 8 bytes
        'eapol_payload'  — full EAPOL frame bytes (for hashcat)

    Returns None if parsing fails.
    """
    ft = get_frame_type(packet)
    if ft is None or ft[0] != 2:
        return None

    header_len = 26 if (ft[1] & 0x08) else 24
    eapol_start = header_len + 8  # skip LLC/SNAP

    # Minimum EAPOL-Key frame: 4 (EAPOL hdr) + 1 (desc type) + 2 (key info)
    #   + 2 (key len) + 8 (replay) + 32 (nonce) + 16 (IV) + 8 (RSC)
    #   + 8 (reserved) + 16 (MIC) + 2 (key data len) = 99 bytes
    if len(packet) < eapol_start + 99:
        return None

    eapol_frame = packet[eapol_start:]
    body_len = struct.unpack('>H', eapol_frame[2:4])[0]

    # Full EAPOL payload = Version(1) + Type(1) + Length(2) + body
    full_eapol = eapol_frame[:4 + body_len]

    # Offsets within EAPOL body (after 4-byte EAPOL header):
    #   +0:   Descriptor Type (1)
    #   +1:   Key Information (2)
    #   +3:   Key Length (2)
    #   +5:   Replay Counter (8)
    #   +13:  Key Nonce (32)
    #   +45:  Key IV (16)
    #   +61:  Key RSC (8)
    #   +69:  Reserved (8)
    #   +77:  Key MIC (16)
    #   +93:  Key Data Length (2)
    #   +95:  Key Data (variable)

    body = eapol_frame[4:]

    if len(body) < 95:
        return None

    key_info = struct.unpack('>H', body[1:3])[0]
    replay   = body[5:13]
    nonce    = body[13:45]
    mic      = body[77:93]
    kd_len   = struct.unpack('>H', body[93:95])[0]

    # Determine if this is ANonce or SNonce based on message type
    # For now, store as generic 'nonce'; the caller (handshake.py)
    # determines which it is based on message number.
    result = {
        'anonce':         nonce,
        'snonce':         nonce,
        'mic':            mic,
        'key_info':       key_info,
        'replay_counter': replay,
        'eapol_payload':  bytes(full_eapol),
    }

    return result

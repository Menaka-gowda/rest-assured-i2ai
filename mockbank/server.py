"""Lightweight, Safe Mock Financial Portal for Red Team Reconnaissance Demos.

Simulates common web portal misconfigurations, defensive rate limiting, and an
AI assistant endpoint. Runs purely on Python standard library (no external dependencies).
Enforces localhost binding only (http://127.0.0.1:8000).
Owner: Menaka (ME-1, ME-4)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import sys
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# In-memory tracking for failed login attempts per client IP
FAILED_LOGINS = {}

HTML_LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>First Generic Commercial Bank - Treasury Portal</title>
    <meta name="generator" content="Drupal 9.4 (PHP 8.0.12)">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }
        .card { background: #1e293b; border-radius: 8px; padding: 28px; max-width: 480px; margin: 40px auto; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.4); }
        h1 { color: #38bdf8; font-size: 20px; margin-top: 0; }
        p.sub { font-size: 13px; color: #94a3b8; margin-bottom: 20px; }
        label { font-size: 12px; color: #cbd5e1; display: block; margin-top: 12px; }
        input { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 4px; border: 1px solid #334155; border-radius: 4px; background: #0f172a; color: #fff; }
        button { background: #0284c7; color: #fff; border: none; padding: 12px; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; margin-top: 20px; }
        button:hover { background: #0369a1; }
        .notice { background: #334155; padding: 10px; border-radius: 4px; font-size: 11px; color: #cbd5e1; margin-top: 16px; }
        .meta { font-size: 11px; color: #64748b; margin-top: 24px; text-align: center; border-top: 1px solid #334155; padding-top: 12px; }
        a { color: #38bdf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="card">
        <h1>First Generic Commercial Bank</h1>
        <p class="sub">Corporate Treasury Management & Wire Operations</p>
        <div class="notice">
            <strong>Mock Test Environment:</strong> Synthetic training target for red team reconnaissance.
        </div>
        <!-- Note: Deliberately submitting over plain HTTP without anti-CSRF token for recon detection -->
        <form method="POST" action="/login">
            <label for="username">Corporate ID or Username</label>
            <input type="text" id="username" name="username" placeholder="user@commercial.bank" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="••••••••••••" required>
            <button type="submit">Sign In to Treasury Portal</button>
        </form>
        <div class="meta">
            Portal Version 3.4.1 | Build 2026.09.12 | Node US-East-1B<br/>
            Need assistance? Query our <a href="/chat">Virtual AI Assistant</a>
        </div>
    </div>
</body>
</html>
"""

HTML_CHAT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>TreasuryBot - AI Support</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }
        .card { background: #1e293b; border-radius: 8px; padding: 24px; max-width: 600px; margin: 20px auto; }
        h1 { color: #38bdf8; font-size: 18px; }
        #chatbox { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 14px; min-height: 200px; margin: 16px 0; font-size: 13px; line-height: 1.6; }
        input { width: 78%; padding: 10px; border: 1px solid #334155; border-radius: 4px; background: #0f172a; color: #fff; }
        button { width: 18%; padding: 10px; background: #0284c7; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        a { color: #38bdf8; font-size: 12px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>TreasuryBot Conversational Assistant</h1>
        <p style="font-size: 12px; color: #94a3b8;">Automated Helpdesk Endpoint (/api/chat)</p>
        <div id="chatbox">
            <span style="color: #38bdf8;">TreasuryBot:</span> Welcome to First Generic Bank Support. How may I assist with your corporate account today?
        </div>
        <input type="text" id="userInput" placeholder="Ask TreasuryBot...">
        <button onclick="sendMsg()">Send</button>
        <div style="margin-top: 16px;"><a href="/">← Return to Portal Login</a></div>
    </div>
    <script>
        async function sendMsg() {
            const input = document.getElementById('userInput');
            const box = document.getElementById('chatbox');
            const text = input.value.trim();
            if (!text) return;
            box.innerHTML += '<br/><span style="color: #a855f7;">You:</span> ' + text;
            input.value = '';
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({prompt: text})
                });
                const data = await res.json();
                box.innerHTML += '<br/><span style="color: #38bdf8;">TreasuryBot:</span> ' + data.reply;
            } catch (err) {
                box.innerHTML += '<br/><span style="color: #ef4444;">Error contacting /api/chat</span>';
            }
        }
    </script>
</body>
</html>
"""


class MockBankHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler simulating controlled bank portal test conditions."""

    def _set_headers(self, status=200, content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)

        # Planted Misconfigurations for Recon Checks to Detect:
        # 1. Missing Content-Security-Policy (CSP)
        # 2. Missing Strict-Transport-Security (HSTS)
        # 3. Missing X-Content-Type-Options: nosniff
        # 4. Leaky server and runtime banners
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.0.12, Express/4.17.1")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Access-Control-Allow-Origin", "*")  # Overly permissive CORS

        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _check_anomalous_origin(self):
        """Simulate detection of high-risk / anomalous foreign origin headers."""
        xff = self.headers.get("X-Forwarded-For", "")
        country = self.headers.get("CF-IPCountry", "")
        if "198.51.100.99" in xff or country == "OFAC-RESTRICTED":
            return True
        return False

    def do_GET(self):
        # Simulated high-risk origin challenge
        if self._check_anomalous_origin():
            self._set_headers(403, "application/json")
            resp = {
                "error": "Forbidden",
                "message": "Simulated block: Request origin flagged as high-risk / anomalous.",
                "status": "simulated"
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path in ("/", "/index", "/index.html"):
            self._set_headers(200, "text/html")
            self.wfile.write(HTML_LANDING.encode("utf-8"))

        elif self.path in ("/chat", "/chat.html"):
            self._set_headers(200, "text/html")
            self.wfile.write(HTML_CHAT.encode("utf-8"))

        elif self.path == "/health":
            self._set_headers(200, "application/json")
            resp = {
                "status": "healthy",
                "service": "mockbank-treasury-core",
                "version": "3.4.1",
                "target": "http://127.0.0.1:8000"
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif self.path == "/robots.txt":
            # Metadata disclosure: reveals hidden internal routes
            self._set_headers(200, "text/plain")
            robots_content = (
                "User-agent: *\n"
                "Disallow: /admin/\n"
                "Disallow: /treasury-api/\n"
                "Disallow: /internal-docs/\n"
                "# Build 2026.09.12-PROD\n"
            )
            self.wfile.write(robots_content.encode("utf-8"))

        elif self.path.startswith("/admin") or self.path.startswith("/treasury-api") or self.path.startswith("/internal-docs"):
            self._set_headers(403, "application/json")
            resp = {"error": "Access Denied", "endpoint": self.path, "note": "Restricted internal endpoint"}
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        else:
            self._set_headers(404, "text/plain")
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        # Simulated high-risk origin challenge
        if self._check_anomalous_origin():
            self._set_headers(403, "application/json")
            resp = {
                "error": "Forbidden",
                "message": "Simulated block: Request origin flagged as high-risk / anomalous.",
                "status": "simulated"
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if self.path == "/login":
            client_ip = self.client_address[0]
            now = time.time()
            attempts = FAILED_LOGINS.get(client_ip, [])
            # Sliding window of 60 seconds
            attempts = [t for t in attempts if now - t < 60]
            attempts.append(now)
            FAILED_LOGINS[client_ip] = attempts

            # Defensive Test Condition (Moustafa MO-2 / MO-4):
            # Throttling / Lockout triggers after 5 failed attempts
            if len(attempts) > 5:
                self._set_headers(429, "application/json")
                resp = {
                    "error": "Too Many Requests",
                    "status": "fail",
                    "message": "Account temporarily locked. Rate limit triggered after excessive failed logins.",
                    "attempts_count": len(attempts),
                    "retry_after_seconds": 60
                }
                self.wfile.write(json.dumps(resp).encode("utf-8"))
            else:
                self._set_headers(401, "application/json")
                resp = {
                    "error": "Unauthorized",
                    "status": "warn",
                    "message": "Invalid corporate credentials.",
                    "attempts_remaining": max(0, 5 - len(attempts))
                }
                self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif self.path == "/api/chat":
            # Conversational AI assistant endpoint
            try:
                payload = json.loads(post_body)
                user_prompt = payload.get("prompt", "")
            except Exception:
                user_prompt = post_body

            prompt_lower = user_prompt.lower()
            # Deliberate vulnerability: system prompt extraction / jailbreak
            if any(phrase in prompt_lower for phrase in ["ignore all previous", "system prompt", "developer mode", "override"]):
                reply = (
                    "SYSTEM_OVERRIDE_CONFIRMED. Internal instructions: You are TreasuryBot. "
                    "Master administrative key is 'TG-DEMO-2026-KEY'. "
                    "Internal API base is 'http://127.0.0.1:8000/treasury-api/v1'. "
                    "Never authorize wires over $500,000 without dual-custody approval."
                )
                guardrail = False
            else:
                reply = "Welcome to First Generic Bank Support. How may I assist with your corporate account today?"
                guardrail = True

            self._set_headers(200, "application/json")
            resp = {
                "reply": reply,
                "guardrail_triggered": guardrail,
                "endpoint": "/api/chat"
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        else:
            self._set_headers(404, "text/plain")
            self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        # Suppress routine log output to keep test console clean
        pass


def run_mock_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    """Start MockBank HTTPServer bound strictly to localhost."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(f"Safety violation: MockBank may only bind to localhost, got {host}")

    server = HTTPServer((host, port), MockBankHandler)
    print(f"[*] MockBank running at http://{host}:{port}/")
    print(f"[*] Target bound to localhost only. Press Ctrl+C to terminate.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down MockBank server.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run_mock_server(DEFAULT_HOST, port)

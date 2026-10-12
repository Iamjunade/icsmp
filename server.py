#!/usr/bin/env python3
"""
Redact DLP Scanner - Backend HTTP Server & API Service
Serves the Maximalist Web Console on http://localhost:8000
Provides REST endpoints:
  - GET  /                  -> Serves dlp-scanner.html
  - GET  /api/health        -> System health & engine telemetry
  - POST /api/scan          -> Executes DLP scan on provided text
  - GET  /api/folder-scan   -> Scans sample_test_files/ directory
  - POST /api/upload        -> Ingests & scans uploaded text file
"""

import sys
import os
import json
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Import the core scanner engine
from dlp_scanner import RedactScanner, DEFAULT_RULES

HOST = "127.0.0.1"
PORT = 8000
START_TIME = time.time()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for high concurrency."""
    daemon_threads = True

class DLPRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS and no-cache headers for smooth local development
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        # Route: Root / -> serve dlp-scanner.html
        if self.path == "/" or self.path == "/index.html":
            html_path = os.path.join(os.path.dirname(__file__), "dlp-scanner.html")
            try:
                with open(html_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                self.send_error(500, f"Error loading dlp-scanner.html: {e}")
                return

        # Route: Health check API
        if self.path == "/api/health":
            resp = {
                "status": "ONLINE",
                "service": "Redact Mini DLP Backend Engine",
                "uptime_seconds": round(time.time() - START_TIME, 2),
                "engine": "Python 3.11 Standard Sandboxed",
                "algorithms": ["Verhoeff (Dihedral D5)", "Luhn (ISO/IEC 7812)"],
                "endpoints": ["/api/health", "/api/scan", "/api/folder-scan"]
            }
            self._send_json(resp)
            return

        # Route: Folder scan API
        if self.path.startswith("/api/folder-scan"):
            folder_path = os.path.join(os.path.dirname(__file__), "sample_test_files")
            scanner = RedactScanner()
            supported_exts = {".txt", ".csv", ".log", ".json", ".md"}
            results = []

            for root, _, files in os.walk(folder_path):
                for file in files:
                    _, ext = os.path.splitext(file)
                    if ext.lower() in supported_exts:
                        fp = os.path.join(root, file)
                        try:
                            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                                text = f.read(200000)
                            scan_res = scanner.scan_text(text)
                            scan_res["filename"] = file
                            scan_res["filepath"] = fp
                            results.append(scan_res)
                        except Exception as ex:
                            results.append({"filename": file, "error": str(ex), "verdict": "ERROR"})

            self._send_json({
                "folder": folder_path,
                "file_count": len(results),
                "results": results
            })
            return

        # Fallback to standard static file server
        super().do_GET()

    def do_POST(self):
        # Route: Scan API
        if self.path == "/api/scan":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                data = json.loads(body.decode("utf-8"))

                text = data.get("text", "")
                custom_rules = data.get("rules", None)
                custom_regex = data.get("custom_regex", None)

                scanner = RedactScanner(rules=custom_rules, custom_regex=custom_regex)
                result = scanner.scan_text(text)

                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e), "verdict": "ERROR"}, status=400)
            return

        self.send_error(404, "Endpoint not found")

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run():
    # Ensure Windows console encoding supports utf-8
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    server_address = (HOST, PORT)
    httpd = ThreadedHTTPServer(server_address, DLPRequestHandler)
    print("=" * 70)
    print("  ⚡ REDACT DLP SCANNER // BACKEND ENGINE LAUNCHED")
    print(f"  🔗 Server URL    : http://{HOST}:{PORT}")
    print(f"  🔗 Localhost Web : http://localhost:{PORT}")
    print(f"  📡 API Endpoint  : http://localhost:{PORT}/api/scan")
    print(f"  🩺 Health Check  : http://localhost:{PORT}/api/health")
    print("=" * 70)
    print("  Server is actively listening for incoming HTTP requests...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == "__main__":
    run()

from http.server import BaseHTTPRequestHandler
import json
import time

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        response = {
            "status": "ONLINE",
            "service": "Redact Mini DLP Vercel Serverless Engine",
            "deployed_on": "Vercel Cloud",
            "engine": "Python 3.11 Serverless",
            "algorithms": ["Verhoeff (Dihedral D5)", "Luhn (ISO/IEC 7812)"]
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))

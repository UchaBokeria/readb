#!/usr/bin/env python3
"""Local companion design preview. No device bridge, credentials or live actions."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--port', type=int, default=8796)
a = p.parse_args()
class Preview(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/style.css':
            content = (ROOT / 'web/style.css').read_bytes() + b'\n' + (ROOT / 'android/assets/companion/style.css').read_bytes()
            kind = 'text/css'
        elif self.path in ('/', '/app.js'):
            content = (ROOT / 'android/assets/companion' / ('index.html' if self.path == '/' else 'app.js')).read_bytes()
            kind = 'text/html' if self.path == '/' else 'text/javascript'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)
    def log_message(self, *_):
        pass
print(f'Companion preview http://127.0.0.1:{a.port}', flush=True)
ThreadingHTTPServer(('127.0.0.1', a.port), Preview).serve_forever()

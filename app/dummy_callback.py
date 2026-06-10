#dummy_callback.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Dummy callback")

if __name__ == "__main__":
    server = HTTPServer(("localhost", 4000), Handler)
    print("Dummy callback listening on http://localhost:4000/callback")
    server.serve_forever()
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import re 

TARGET_SERVER_URL = "http://localhost:8080" 
WAF_PORT = 8000
LOG_FILE = "waf.log"

IP_BLOCKLIST = {
    #"127.0.0.1"  # Example: Block yourself for testing
    # Add other known bad IPs here, e.g., "192.168.1.100"
}

MALICIOUS_SIGNATURES = [
    
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE), 
    re.compile(r"\b(UNION\s+SELECT)\b", re.IGNORECASE),
 
    re.compile(r"(<|%3C)script(>|%3E)", re.IGNORECASE),
    re.compile(r"<[^>]+(onerror|onload|onmouseover)\s*=", re.IGNORECASE),

    re.compile(r"\.\./|\.\.\\") 
]


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def log_event(ip, path, reason):
    
    logging.info(f"[{reason}] IP: {ip}, Path: {path}")
    print(f"[{reason}] IP: {ip}, Path: {path}") 

class WAFProxy(BaseHTTPRequestHandler):

    def is_malicious(self, path, body=None):
      
        content_to_check = path
        if body:
            try:
                content_to_check += " " + body.decode('utf-8', 'ignore')
            except Exception:
                pass 

        
        for signature in MALICIOUS_SIGNATURES:
            match = signature.search(content_to_check)
            if match:
                
                return match.group(0) 
        
        return None

    def send_blocked_response(self, reason):
        
        self.send_response(403) 
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>403 Forbidden</h1>")
        self.wfile.write(b"<p>Your request was blocked by the WAF.</p>")
        self.wfile.write(f"<p>Reason: {reason}</p>".encode('utf-8'))

    def handle_request(self, method):
        
        client_ip = self.client_address[0]
        
        if client_ip in IP_BLOCKLIST:
            reason = "IP Blocklist"
            log_event(client_ip, self.path, f"BLOCKED ({reason})")
            self.send_blocked_response(reason)
            return

        body = None
        if method == 'POST':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
            except Exception as e:
                log_event(client_ip, self.path, f"ERROR (Reading body: {e})")
                self.send_error(400, "Bad Request")
                return

        malicious_pattern = self.is_malicious(self.path, body)
        if malicious_pattern:
            reason = f"Attack Signature ({malicious_pattern})"
            log_event(client_ip, self.path, f"BLOCKED ({reason})")
            self.send_blocked_response(reason)
            return
      
        try:
            log_event(client_ip, self.path, "ALLOWED")
            
            resp = requests.request(
                method,
                f"{TARGET_SERVER_URL}{self.path}",
                headers=dict(self.headers), 
                data=body,
                allow_redirects=False, 
                timeout=5 
            )

            
            self.send_response(resp.status_code)
            for key, value in resp.headers.items():
                
                if key.lower() not in ('content-encoding', 'transfer-encoding', 'connection'):
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(resp.content)

        except requests.exceptions.ConnectionError:
            log_event(client_ip, self.path, "ERROR (Target server offline)")
            self.send_error(502, "Bad Gateway: Upstream server is offline.")
        except Exception as e:
            log_event(client_ip, self.path, f"ERROR (Proxy error: {e})")
            self.send_error(500, f"Internal Server Error: {e}")

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')
    
    def do_PUT(self):
        self.handle_request('PUT')

    def do_DELETE(self):
        self.handle_request('DELETE')

if __name__ == "__main__":
    httpd = HTTPServer(('localhost', WAF_PORT), WAFProxy)
    print(f"Starting WAF Proxy on http://localhost:{WAF_PORT}...")
    print(f"Logging events to: {LOG_FILE}")
    print(f"Blocking IPs: {IP_BLOCKLIST}")
    print(f"Forwarding clean traffic to: {TARGET_SERVER_URL}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("\nStopping WAF Proxy.")
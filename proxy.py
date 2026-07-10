import http.server
import socketserver
import json
import requests
from urllib.parse import urlparse
from pii_shield import PIIScrubber, AIShield

PORT = 8080

class PIIProxyHandler(http.server.BaseHTTPRequestHandler):
    shield = AIShield()
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body)
        except:
            self.send_error(400, "Invalid JSON")
            return
        
        prompt = data.get("messages", [{"role": "user", "content": ""}])
        if isinstance(prompt, list):
            last_message = prompt[-1].get("content", "")
        else:
            last_message = str(prompt)
        
        result = self.shield.process_request(last_message)
        
        api_key = self.headers.get('Authorization', '').replace('Bearer ', '')
        target_url = "https://api.openai.com/v1/chat/completions"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}" if api_key else ""
        }
        
        modified_data = data.copy()
        if isinstance(modified_data.get("messages"), list):
            for msg in modified_data["messages"]:
                if msg.get("role") == "user":
                    msg["content"] = result["scrubbed_prompt"]
                    break
        
        try:
            response = requests.post(target_url, headers=headers, json=modified_data, timeout=30)
            response_data = response.json()
            
            if "choices" in response_data:
                for choice in response_data["choices"]:
                    if "message" in choice:
                        restored = self.shield.scrubber.restore(choice["message"].get("content", ""))
                        choice["message"]["content"] = restored
            
            self.send_response(response.status_code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())
            
        except Exception as e:
            self.send_error(502, f"Proxy Error: {str(e)}")
    
    def log_message(self, format, *args):
        print(f"[PROXY] {format % args}")


def start_proxy(api_key=None):
    with socketserver.TCPServer(("", PORT), PIIProxyHandler) as httpd:
        print(f"AI Firewall Proxy running on http://localhost:{PORT}")
        print(f"Configure your AI client to use: http://localhost:{PORT}")
        print(f"Press Ctrl+C to stop")
        httpd.serve_forever()


if __name__ == "__main__":
    import sys
    api_key = sys.argv[1] if len(sys.argv) > 1 else None
    start_proxy(api_key)
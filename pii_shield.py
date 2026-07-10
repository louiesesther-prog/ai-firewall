import re
from datetime import datetime

class PIIScrubber:
    def __init__(self):
        self.pii_map = {}
        self.counter = 1
        
        self.patterns = {
            "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "PHONE": r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            "CREDIT_CARD": r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b',
            "SSN": r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            "IP_ADDRESS": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "ADDRESS": r'\b\d{1,5}\s+[\w\s]+(?:Street|St|Ave|Road|Rd|Blvd|Lane|Ln|Dr)\.?\b',
            "DATE_OF_BIRTH": r'\b(?:DOB|Date of Birth|Born)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
            "PASSWORD": r'(?:password|pwd|pass)[:\s]+\S+',
            "API_KEY": r'(?:api[_-]?key|apikey)[:\s]+\S+',
        }
        
        self.placeholder_prefix = {
            "EMAIL": "[EMAIL_ADDR",
            "PHONE": "[PHONE_NUM",
            "CREDIT_CARD": "[CC_NUM",
            "SSN": "[SSN_NUM",
            "IP_ADDRESS": "[IP_ADDR",
            "ADDRESS": "[STREET_ADDR",
            "DATE_OF_BIRTH": "[DOB_VAL",
            "PASSWORD": "[PWD_VAL",
            "API_KEY": "[APIKEY_VAL",
        }
    
    def scrub(self, text):
        self.pii_map.clear()
        self.counter = 1
        
        scrubbed = text
        
        for pii_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, scrubbed, re.IGNORECASE)
            for match in matches:
                original = match.group()
                placeholder = f"{self.placeholder_prefix[pii_type]}_{self.counter}]"
                self.pii_map[placeholder] = original
                scrubbed = scrubbed.replace(original, placeholder)
                self.counter += 1
        
        return scrubbed
    
    def restore(self, text):
        restored = text
        sorted_map = sorted(self.pii_map.items(), key=lambda x: len(x[0]), reverse=True)
        for placeholder, original in sorted_map:
            restored = restored.replace(placeholder, original)
        return restored
    
    def get_pii_map(self):
        return self.pii_map.copy()


class AIShield:
    def __init__(self, api_endpoint="https://api.openai.com/v1/chat/completions"):
        self.scrubber = PIIScrubber()
        self.api_endpoint = api_endpoint
        self.request_log = []
        self.stats = {
            "requests_processed": 0,
            "pii_detected": 0,
            "pii_types": {}
        }
    
    def process_request(self, prompt, api_key=None):
        scrubbed_prompt = self.scrubber.scrub(prompt)
        pii_found = len(self.scrubber.get_pii_map())
        
        self.request_log.append({
            "timestamp": datetime.now().isoformat(),
            "original": prompt,
            "scrubbed": scrubbed_prompt,
            "pii_count": pii_found,
            "pii_map": self.scrubber.get_pii_map()
        })
        
        self.stats["requests_processed"] += 1
        self.stats["pii_detected"] += pii_found
        
        for placeholder, original in self.scrubber.get_pii_map().items():
            pii_type = placeholder.split("_")[0].replace("[", "")
            self.stats["pii_types"][pii_type] = self.stats["pii_types"].get(pii_type, 0) + 1
        
        return {
            "scrubbed_prompt": scrubbed_prompt,
            "pii_map": self.scrubber.get_pii_map(),
            "pii_count": pii_found
        }
    
    def process_response(self, response_text):
        restored = self.scrubber.restore(response_text)
        return {
            "original_response": response_text,
            "restored_response": restored,
            "replacements_made": len(self.scrubber.get_pii_map())
        }
    
    def get_stats(self):
        return self.stats.copy()
    
    def get_logs(self, limit=10):
        return self.request_log[-limit:]
    
    def clear_logs(self):
        self.request_log.clear()
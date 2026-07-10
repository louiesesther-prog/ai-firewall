"""
AI Personal Firewall - Advanced PII Detection Engine
Comprehensive regex-based detection with Faker for realistic replacements
"""

from faker import Faker
import re
import json

class AdvancedPIIGuard:
    def __init__(self):
        self.faker = Faker()
        self.pii_map = {}
        self.counter = 1
        self.stats = {"requests_processed": 0, "pii_detected": 0, "pii_types": {}}
        self.patterns = self._get_patterns()
        self.compiled_patterns = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in self.patterns.items()}

    def _get_patterns(self):
        return {
            "EMAIL_ADDRESS": [r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'],
            "PHONE_NUMBER": [r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'],
            "CREDIT_CARD": [r'\d{4}-\d{4}-\d{4}-\d{4}', r'\d{16}'],
            "SSN": [r'\d{3}-\d{2}-\d{4}'],
            "TAX_ID": [r'(?:TIN|TAX\s*ID)[:\s]*\d{2}-\d{7}'],
            "IBAN": [r'[A-Z]{2}\d{2}[A-Z0-9]{11,30}'],
            "ROUTING_NUMBER": [r'\d{9}'],
            "BANK_ACCOUNT": [r'(?:account|acct)[:\s]*\d{8,17}'],
            "SWIFT_CODE": [r'[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?'],
            "CRYPTO_WALLET": [r'0x[a-fA-F0-9]{40}', r'(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}'],
            "SALARY_INCOME": [r'(?:salary|income|pay)[:\s]*\$[\d,]+'],
            "US_PASSPORT": [r'[A-Z]\d{8}'],
            "DRIVER_LICENSE": [r'(?:driver\'?s?\s*license|dl)[:\s]*[A-Z]?\d{5,9}'],
            "VEHICLE_VIN": [r'[A-HJ-NPR-Z0-9]{17}'],
            "VEHICLE_PLATE": [r'[A-Z]{2,3}-\d{3,4}'],
            "MEDICAL_RECORD": [r'MRN[:\s]*\d+', r'Patient\s*ID[:\s]*\d+'],
            "INSURANCE_ID": [r'(?:insurance|policy)[:\s]*[A-Z0-9]{9,12}'],
            "HEALTHCARE_ACCOUNT": [r'(?:HSA|FSA|HRA)[:\s]*\$?\d+'],
            "IP_ADDRESS": [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'],
            "MAC_ADDRESS": [r'[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}'],
            "STREET_ADDRESS": [r'\d+\s+[\w\s]+(?:Street|St|Ave|Avenue|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\.'],
            "ZIP_CODE": [r'\d{5}(?:-\d{4})?'],
            "PASSWORD": [r'password[:\s]+\S+', r'passwd[:\s]+\S+'],
            "API_KEY": [r'api_key[:\s]+\S+', r'sk-[a-zA-Z0-9]{20,}'],
            "PRIVATE_KEY": [r'-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----'],
            "JWT_TOKEN": [r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'],
            "EMPLOYEE_ID": [r'(?:employee|emp)(?:\s*id)?[:\s]*[A-Z0-9-]{4,10}'],
            "STUDENT_ID": [r'(?:student|stu)(?:\s*id)?[:\s]*[A-Z0-9-]{4,12}'],
            "GPA_GRADE": [r'(?:GPA|grade)[:\s]*(?:\d\.\d)'],
            "CASE_NUMBER": [r'case\s*(?:#|number)[:\s]*[\d\w-]{6,}'],
            "LICENSE_NUMBER": [r'license\s*(?:number|#)[:\s]*[A-Z0-9-]{4,15}'],
            "POLICY_NUMBER": [r'(?:policy|claim)(?:\s*number)?[:\s]*[A-Z0-9-]{6,12}'],
            "DATE_OF_BIRTH": [r'(?:DOB|Date of Birth)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}'],
        }

    def detect_pii(self, text):
        findings = []
        for ptype, patterns in self.compiled_patterns.items():
            for p in patterns:
                for m in p.finditer(text):
                    findings.append({"type": ptype, "start": m.start(), "end": m.end(), "text": m.group()})
        if not findings:
            return []
        sorted_f = sorted(findings, key=lambda x: (x["start"], -(x["end"] - x["start"])))
        result, last_end = [], -1
        for f in sorted_f:
            if f["start"] >= last_end:
                result.append(f)
                last_end = f["end"]
        return result

    def _fake(self, ptype):
        fakes = {
            "EMAIL_ADDRESS": lambda: self.faker.email(),
            "PHONE_NUMBER": lambda: self.faker.phone_number(),
            "CREDIT_CARD": lambda: self.faker.credit_card_number(),
            "SSN": lambda: f"***-**-{self.faker.ssn()[-4:]}",
            "TAX_ID": lambda: f"**-{self.faker.numerify('#######')}",
            "IBAN": lambda: self.faker.iban(),
            "ROUTING_NUMBER": lambda: self.faker.numerify('#########'),
            "BANK_ACCOUNT": lambda: f"****{self.faker.numerify('#####')}",
            "SWIFT_CODE": lambda: self.faker.bban()[:8],
            "CRYPTO_WALLET": lambda: f"0x{self.faker.sha256()[:40]}",
            "SALARY_INCOME": lambda: "$[REDACTED]",
            "US_PASSPORT": lambda: f"{chr(65+self.faker.random_int(0,25))}{self.faker.numerify('########')}",
            "DRIVER_LICENSE": lambda: f"DL{self.faker.numerify('#######')}",
            "VEHICLE_VIN": lambda: self.faker.vin(),
            "VEHICLE_PLATE": lambda: self.faker.license_plate(),
            "MEDICAL_RECORD": lambda: f"MRN{self.faker.numerify('######')}",
            "INSURANCE_ID": lambda: f"INS{self.faker.numerify('######')}",
            "HEALTHCARE_ACCOUNT": lambda: "$[REDACTED]",
            "IP_ADDRESS": lambda: self.faker.ipv4(),
            "MAC_ADDRESS": lambda: self.faker.mac_address(),
            "STREET_ADDRESS": lambda: self.faker.street_address(),
            "ZIP_CODE": lambda: self.faker.zipcode(),
            "PASSWORD": lambda: "[REDACTED]",
            "API_KEY": lambda: "[REDACTED_API_KEY]",
            "PRIVATE_KEY": lambda: "[REDACTED_PRIVATE_KEY]",
            "JWT_TOKEN": lambda: "[REDACTED_JWT]",
            "EMPLOYEE_ID": lambda: f"EMP{self.faker.numerify('#####')}",
            "STUDENT_ID": lambda: f"STU{self.faker.numerify('#####')}",
            "GPA_GRADE": lambda: "[GRADE_REDACTED]",
            "CASE_NUMBER": lambda: f"CASE-{self.faker.year()}-CV-{self.faker.numerify('###')}",
            "LICENSE_NUMBER": lambda: f"LIC{self.faker.numerify('######')}",
            "POLICY_NUMBER": lambda: f"POL{self.faker.numerify('######')}",
            "DATE_OF_BIRTH": lambda: self.faker.date(pattern="%Y-%m-%d"),
        }
        return fakes.get(ptype, lambda: self.faker.name())()

    def scrub(self, text, use_fake=True):
        self.pii_map, self.counter = {}, 1
        scrubbed, offset = text, 0
        for f in sorted(self.detect_pii(text), key=lambda x: x["start"], reverse=True):
            fake = self._fake(f["type"]) if use_fake else f"[{f['type']}_{self.counter}]"
            self.pii_map[fake] = f["text"]
            start, end = f["start"] + offset, f["end"] + offset
            scrubbed = scrubbed[:start] + fake + scrubbed[end:]
            offset += len(fake) - (f["end"] - f["start"])
            self.stats["pii_detected"] += 1
            self.stats["pii_types"][f["type"]] = self.stats["pii_types"].get(f["type"], 0) + 1
            self.counter += 1
        return scrubbed

    def restore(self, text):
        restored = text
        for p, o in sorted(self.pii_map.items(), key=lambda x: len(x[0]), reverse=True):
            restored = restored.replace(p, o)
        return restored

    def process(self, text, use_fake=True):
        self.stats["requests_processed"] += 1
        return self.scrub(text, use_fake)

    def get_stats(self):
        return self.stats.copy()

    def reset_stats(self):
        self.stats = {"requests_processed": 0, "pii_detected": 0, "pii_types": {}}

def demo():
    print("=" * 70)
    print("AI PERSONAL FIREWALL - Comprehensive PII Detection")
    print("=" * 70)
    
    guard = AdvancedPIIGuard()
    
    tests = [
        ("Email + SSN", "Contact john@test.com, SSN: 123-45-6789"),
        ("Credit Card", "Card: 4532-1234-5678-9010"),
        ("Bank", "Account: 9876543210, Routing: 021000021"),
        ("Tax ID", "TIN: 12-3456789, Salary: $75,000/year"),
        ("Documents", "Passport: A12345678, DL: D123456789"),
        ("Vehicle", "VIN: 1HGBH41JXMN109186, Plate: ABC-1234"),
        ("Medical", "MRN: 123456789, Insurance: INS123456789"),
        ("API Key", "API: sk-abc123xyz456def789ghij012klmno"),
        ("Employee", "EMP-12345, Salary: $95,000/year"),
        ("Crypto", "ETH: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e1"),
    ]
    
    guard.reset_stats()
    
    print(f"\n[TESTING {len(tests)} SCENARIOS]")
    print("-" * 70)
    
    for name, prompt in tests:
        scrubbed = guard.process(prompt)
        print(f"\n{name}:")
        print(f"  IN:  {prompt}")
        print(f"  OUT: {scrubbed}")
    
    print("\n" + "=" * 70)
    print("[STATISTICS]")
    print("-" * 70)
    stats = guard.get_stats()
    print(f"Requests: {stats['requests_processed']}, PII Detected: {stats['pii_detected']}")
    print("\nBy Type:")
    for t, c in sorted(stats['pii_types'].items()):
        print(f"  ✓ {t}: {c}")
    
    print("\n" + "=" * 70)
    print("[ALL 30+ PII TYPES SUPPORTED]")
    print("-" * 70)
    for ptype in sorted(guard.patterns.keys()):
        print(f"  ✓ {ptype}")

if __name__ == "__main__":
    demo()

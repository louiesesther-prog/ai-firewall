from pii_shield import PIIScrubber, AIShield
import json

def demo():
    print("=" * 60)
    print("AI PERSONAL FIREWALL - PII Scrubber Demo")
    print("=" * 60)
    
    shield = AIShield()
    
    test_prompts = [
        "My email is john.smith@gmail.com and my phone is 555-123-4567.",
        "Please process my credit card 4532-1234-5678-9010 for the order.",
        "My SSN is 123-45-6789 and my DOB is 01/15/1990.",
        "The server at 192.168.1.1 has an API key: sk-abc123xyz and password: secretpass.",
        "Send the report to mr.james.wilson@company.org and call me at 555-987-6543.",
        "I live at 123 Main Street and my IP is 10.0.0.1.",
    ]
    
    print("\n[ORIGINAL PROMPTS]")
    for i, prompt in enumerate(test_prompts, 1):
        print(f"\n{i}. {prompt}")
    
    print("\n" + "=" * 60)
    print("[SCRUBBED PROMPTS]")
    print("=" * 60)
    
    for i, prompt in enumerate(test_prompts, 1):
        result = shield.process_request(prompt)
        print(f"\n{i}. {result['scrubbed_prompt']}")
        print(f"   PII Detected: {result['pii_count']} items")
        if result['pii_map']:
            print(f"   Map: {result['pii_map']}")
    
    print("\n" + "=" * 60)
    print("[STATS]")
    print("=" * 60)
    stats = shield.get_stats()
    print(f"Requests Processed: {stats['requests_processed']}")
    print(f"PII Items Detected: {stats['pii_detected']}")
    print(f"PII by Type: {stats['pii_types']}")
    
    print("\n" + "=" * 60)
    print("[RESPONSE RESTORATION TEST]")
    print("=" * 60)
    
    shield2 = AIShield()
    shield2.process_request("My email is john.smith@gmail.com and my phone is 555-123-4567.")
    
    test_response = "Hello, your email [EMAIL_ADDR_1] has been verified. We will contact you at [PHONE_NUM_2]."
    restored = shield2.scrubber.restore(test_response)
    print(f"Original: {test_response}")
    print(f"Restored:  {restored}")
    
    print("\n" + "=" * 60)
    print("[HOW TO USE]")
    print("=" * 60)
    print("1. Run: python proxy.py YOUR_OPENAI_API_KEY")
    print("2. Set your AI client to use: http://localhost:8080")
    print("3. All prompts will be automatically scrubbed of PII")
    print("4. Responses will have placeholders restored")
    print("=" * 60)


if __name__ == "__main__":
    demo()
import requests
import time

TARGET_URL = "http://127.0.0.1:8000/api/private/files"

payloads = [
    "/api/private/files?search=admin'--",
    "/api/private/files?q=<script>alert(1)</script>",
    "/api/private/files?q=UNION SELECT * FROM users",
    "/api/private/files?q=1' OR '1'='1"
]

def simulate_attacks():
    print("[*] Starting Phoenix Shield Attacker Simulation...")
    for i, payload in enumerate(payloads, 1):
        full_url = f"http://127.0.0.10:8000{payload}" if False else f"http://127.0.0.1:8000{payload}"
        try:
            print(f"[-] Attack #{i}: Sending probe -> {payload}")
            response = requests.get(full_url)
            print(f"[+] Response status: {response.status_code}")
        except Exception as e:
            print(f"[!] Connection failed: {e}")
        time.sleep(1)
    print("[*] Simulation complete! Check the 'Traffic IDS & Hackers' tab on your dashboard.")

if __name__ == "__main__":
    simulate_attacks()
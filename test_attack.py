"""
test_attack.py — Simulates a brute-force login attack for demo purposes.
Updated to handle CSRF protection (extracts token from login page first).
"""
import requests
from html.parser import HTMLParser

BASE_URL = "http://127.0.0.1:5000"

# ── Helper: extract CSRF token from login page ──────────────
class CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token = None

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            attrs_dict = dict(attrs)
            if attrs_dict.get("name") == "csrf_token":
                self.csrf_token = attrs_dict.get("value")

def get_csrf_token(session):
    resp = session.get(f"{BASE_URL}/login")
    parser = CSRFParser()
    parser.feed(resp.text)
    return parser.csrf_token

# ── Main attack simulation ───────────────────────────────────
session = requests.Session()

print("=" * 55)
print("   AI SHIELD — Brute Force Attack Simulation")
print("=" * 55)
print()

for i in range(10):
    # Fetch a fresh CSRF token for each attempt
    csrf_token = get_csrf_token(session)
    if not csrf_token:
        print(f"Attempt {i+1}: ⚠️  Could not retrieve CSRF token.")
        break

    response = session.post(
        f"{BASE_URL}/login",
        data={
            "username":   "SANU",
            "password":   f"wrongpassword{i}",
            "csrf_token": csrf_token,
        },
        allow_redirects=True
    )

    print(f"Attempt {i+1:>2} | Status: {response.status_code} | URL: {response.url}")

    if "Suspicious activity detected" in response.text:
        print(f"          🔴 BLOCKED by AI Shield at attempt {i+1}!")
        break
    elif "Invalid username or password" in response.text:
        print(f"          ✅ Wrong password accepted (not blocked yet)")
    elif "blocked by the administrator" in response.text:
        print(f"          🔴 BLOCKED — IP is manually blacklisted.")
        break
    else:
        print(f"          ⚠️  Unexpected response — check server logs")

print()
print("Simulation complete.")
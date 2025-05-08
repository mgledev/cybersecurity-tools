import requests
import time

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# Set your API keys here or load from env/config
HIBP_API_KEY = "YOUR_HIBP_KEY"
ABUSE_API_KEY = "YOUR_ABUSE_KEY"

headers_hibp = {
    "hibp-api-key": HIBP_API_KEY,
    "User-Agent": "DumpFerret"
}

headers_abuse = {
    "Key": ABUSE_API_KEY,
    "Accept": "application/json"
}

def check_email_hibp(email: str) -> list:
    url = HIBP_URL + email
    try:
        resp = requests.get(url, headers=headers_hibp, params={"truncateResponse": "true"})
        if resp.status_code == 200:
            return [b["Name"] for b in resp.json()]
        elif resp.status_code == 404:
            return []
        else:
            return [f"Error: {resp.status_code}"]
    except Exception as e:
        return [f"Exception: {e}"]

def check_ip_abuseipdb(ip: str) -> dict:
    try:
        resp = requests.get(ABUSE_URL, headers=headers_abuse, params={"ipAddress": ip, "maxAgeInDays": 90})
        if resp.status_code == 200:
            data = resp.json()["data"]
            return {
                "abuseConfidence": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "domain": data.get("domain"),
                "totalReports": data.get("totalReports"),
            }
        else:
            return {"error": f"{resp.status_code}"}
    except Exception as e:
        return {"exception": str(e)}

if __name__ == "__main__":
    print("[+] Testing enrichment")
    print(check_email_hibp("test@example.com"))
    print(check_ip_abuseipdb("8.8.8.8"))
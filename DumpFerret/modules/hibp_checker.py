import requests
import time

def hibp_check(api_key: str, emails: list[str]) -> dict:
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "DumpFerret/1.0"
    }
    results = {}
    for email in emails:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            results[email] = [entry["Name"] for entry in r.json()]
        elif r.status_code == 404:
            results[email] = []  # not breached
        else:
            results[email] = {"error": f"{r.status_code} {r.reason}"}
        time.sleep(2)
    return results

import requests
import time

def vt_lookup(api_key: str, indicators: list[str]) -> dict:
    headers = {"x-apikey": api_key}
    results = {}
    for ind in indicators:
        ind_type = "files" if len(ind) in {32, 40, 64} else "ip_addresses"
        url = f"https://www.virustotal.com/api/v3/{ind_type}/{ind}"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            result = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results[ind] = result
        else:
            results[ind] = {"error": f"{r.status_code} {r.reason}"}
        time.sleep(15)  # avoid rate limiting (4 req/min public API)
    return results

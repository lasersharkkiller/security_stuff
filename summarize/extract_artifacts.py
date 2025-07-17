import os
import re
import json
import requests
import ipaddress
from pathlib import Path
from time import sleep
from dotenv import load_dotenv

# === LOAD API KEY FROM .env ===
load_dotenv()
APIKEY = os.getenv("APIVOID_API_KEY")

if not APIKEY:
    print(" APIVOID_API_KEY not found in .env file.")
    exit(1)

# === CONFIGURATION ===
SLEEP_TIME = 1                        # Throttle API calls to avoid rate limiting
OUTPUT_JSON = "apivoid_results.json"  # Output filename
CURRENT_DIR = Path('.')               # Current working directory

# === REGEX PATTERNS ===
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

# === STORAGE ===
ips = set()
domains = set()
results = {"ips": [], "domains": []}

# === UTILITY ===
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

# === PARSE TXT FILES ===
for file in CURRENT_DIR.glob("*.txt"):
    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        ips.update(re.findall(IP_REGEX, content))
        domains.update(re.findall(DOMAIN_REGEX, content))

# === CLEAN DOMAINS ===
filtered_domains = {
    d for d in domains
    if not re.match(IP_REGEX, d) and not d.endswith(".wixstatic.com")
}

# === APIVOID FUNCTIONS ===
def query_apivoid_ip(ip):
    url = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={APIKEY}&ip={ip}"
    r = requests.get(url)
    if r.ok:
        data = r.json().get("data", {}).get("report", {})
        result = {
            "ip": ip,
            "blacklist_hits": data.get("blacklists", {}).get("engines_count", "N/A"),
            "asn": data.get("information", {}).get("asn", "N/A"),
            "country": data.get("information", {}).get("country_name", "N/A"),
            "threat_category": data.get("risk_analysis", {}).get("risk_score_result", {}).get("category", "N/A")
        }
        results["ips"].append(result)
    else:
        results["ips"].append({"ip": ip, "error": f"{r.status_code} - {r.text}"})


def query_apivoid_domain(domain):
    url = f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={APIKEY}&host={domain}"
    r = requests.get(url)
    if r.ok:
        data = r.json().get("data", {}).get("report", {})
        result = {
            "domain": domain,
            "blacklist_hits": data.get("blacklists", {}).get("engines_count", "N/A"),
            "server_ip": data.get("server", {}).get("ip", "N/A"),
            "threat_category": data.get("risk_score", {}).get("category", "N/A")
        }
        results["domains"].append(result)
    else:
        results["domains"].append({"domain": domain, "error": f"{r.status_code} - {r.text}"})


# === MAIN EXECUTION ===
if __name__ == "__main__":
    print("\n--- Querying IPs ---")
    for ip in sorted(ips):
        if not is_public_ip(ip):
            continue
        query_apivoid_ip(ip)
        sleep(SLEEP_TIME)

    print("\n--- Querying Domains ---")
    for domain in sorted(filtered_domains):
        query_apivoid_domain(domain)
        sleep(SLEEP_TIME)

    # Save results to JSON
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n Results saved to: {OUTPUT_JSON}")

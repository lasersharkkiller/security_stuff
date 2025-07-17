import os
import re
import json
import requests
import ipaddress
from pathlib import Path
from time import sleep
from dotenv import load_dotenv
from colorama import Fore, Style, init

init(autoreset=True)

# === LOAD .env ===
load_dotenv()
APIKEY = os.getenv("APIVOID_API_KEY")

if not APIKEY:
    print(" APIVOID_API_KEY not found in .env")
    exit(1)

# === CONFIGURATION ===
SLEEP_TIME = 1
OUTPUT_JSON = "apivoid_results.json"
CURRENT_DIR = Path('.')
BLACKLISTED_DOMAINS = {"proton.me"}

# === PUBLIC TLD LIST (shortened for space — you can expand) ===
VALID_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'co', 'io', 'ai', 'info', 'biz',
    'me', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'it', 'in', 'ru', 'cn', 'br',
    'xyz', 'site', 'tech', 'dev', 'app', 'store', 'online', 'tv', 'live'
}

# === REGEX ===
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

# === UTILITIES ===
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def is_valid_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) < 2:
        return False
    tld = parts[-1]
    sld = parts[-2]
    if tld not in VALID_TLDS:
        return False
    if len(sld) < 2 or sld.istitle():
        return False
    if domain in BLACKLISTED_DOMAINS:
        return False
    return True

def colorize(score):
    if score == 0:
        return Fore.GREEN
    elif score == 100:
        return Fore.RED
    else:
        return Fore.YELLOW

# === STORAGE ===
ips = set()
domains = set()
results = {"ips": [], "domains": []}

# === EXTRACT FROM FILES ===
for file in CURRENT_DIR.glob("*.txt"):
    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        ips.update(re.findall(IP_REGEX, content))
        domains.update(re.findall(DOMAIN_REGEX, content))

# === FILTER DOMAINS ===
filtered_domains = {
    d for d in domains
    if not re.match(IP_REGEX, d)
    and not d.endswith(".wixstatic.com")
    and is_valid_domain(d)
}

# === APIVOID LOOKUPS ===
def query_apivoid_ip(ip):
    url = f"https://api.apivoid.com/v2/ip-reputation?key={APIKEY}&ip={ip}"
    r = requests.get(url)
    if r.ok:
        data = r.json().get("data", {}).get("report", {})
        score = data.get("risk_analysis", {}).get("risk_score", {}).get("result", 0)
        color = colorize(score)
        print(f"{color}[IP] {ip} → Threat Score: {score}{Style.RESET_ALL}")

        results["ips"].append({
            "ip": ip,
            "threat_score": score,
            "blacklist_hits": data.get("blacklists", {}).get("engines_count", "N/A"),
            "asn": data.get("information", {}).get("asn", "N/A"),
            "country": data.get("information", {}).get("country_name", "N/A"),
            "threat_category": data.get("risk_analysis", {}).get("risk_score_result", {}).get("category", "N/A")
        })
    else:
        print(f"{Fore.RED}[IP] {ip} → Error: {r.status_code} - {r.text}")
        results["ips"].append({"ip": ip, "error": f"{r.status_code} - {r.text}"})


def query_apivoid_domain(domain):
    url = f"https://api.apivoid.com/v2/domain-reputation?key={APIKEY}&host={domain}"
    r = requests.get(url)
    if r.ok:
        data = r.json().get("data", {}).get("report", {})
        score = data.get("risk_score", {}).get("result", 0)
        color = colorize(score)
        print(f"{color}[DOMAIN] {domain} → Threat Score: {score}{Style.RESET_ALL}")

        results["domains"].append({
            "domain": domain,
            "threat_score": score,
            "blacklist_hits": data.get("blacklists", {}).get("engines_count", "N/A"),
            "server_ip": data.get("server", {}).get("ip", "N/A"),
            "threat_category": data.get("risk_score", {}).get("category", "N/A")
        })
    else:
        print(f"{Fore.RED}[DOMAIN] {domain} → Error: {r.status_code} - {r.text}")
        results["domains"].append({"domain": domain, "error": f"{r.status_code} - {r.text}"})


# === MAIN ===
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

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n Results saved to: {OUTPUT_JSON}")

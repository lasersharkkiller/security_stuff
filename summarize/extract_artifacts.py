import os
import re
import json
import requests
import ipaddress
from pathlib import Path
from time import sleep
from dotenv import load_dotenv

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

# === PUBLIC TLD LIST (from IANA root zone) ===
VALID_TLDS = {
    'com','org','net','int','edu','gov','mil','co','io','ai','info','biz','us','uk','de','fr','ca',
    'au','cn','jp','kr','es','br','tv','me','xyz','site','tech','dev','app','online','store','pro',
    'name','club','live','cloud','digital','media','today','news','services','solutions','support',
    'systems','world','zone','in','it','ru','ch','se','no','nl','pl','eu','be','at','nz','mx','za',
    'tr','id','sg','ph','hk','tw','vn','ir','sa','ae','il','pt','gr','cz','hu','fi','ro','sk','bg',
    'lt','lv','ee','hr','si','rs','ba','ge','am','kz','by','ua','pk','bd','lk','np','th','my','kh',
    'mm','la','af','uz','tm','mn','kg','tj','az','iq','sy','ye','jo','lb','om','qa','kw','bh','dz',
    'ma','tn','eg','ng','ke','gh','ug','tz','cm','sn','ci','zm','zw','mw','ml','ne','bw','na','ao',
    'et','so','sd','ss','cd','cg','ga','gn','gm','sl','lr','bi','rw','dj','er'
}

# === REGEX PATTERNS ===
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

# === UTILITIES ===
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def is_valid_domain(domain):
    parts = domain.lower().split('.')
    return len(parts) >= 2 and parts[-1] in VALID_TLDS

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
    url = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={APIKEY}&ip={ip}"
    r = requests.get(url)
    if r.ok:
        data = r.json().get("data", {}).get("report", {})
        results["ips"].append({
            "ip": ip,
            "blacklist_hits": data.get("blacklists", {}).get("engines_count", "N/A"),
            "asn": data.get("information", {}).get("asn", "N/A"),
            "country": data.get("information", {}).get("country_name", "N/A"),
            "threat_category": data.get("risk_analysis", {}).get("risk_score_result", {}).get("category", "N/A")
        })
    else:
        results["ips"].append({"ip": ip, "error": f"{r.status_code} - {r.text}"})


def query_apivoid_domain(domain):
    url = f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={APIKEY}&host={domain}"
    r = requests.get(url)
    if r.ok:
        data = r.json().get("data", {}).get("report", {})
        results["domains"].append({
            "domain": domain,
            "blacklist_hits": data.get("blacklists", {}).get("engines_count", "N/A"),
            "server_ip": data.get("server", {}).get("ip", "N/A"),
            "threat_category": data.get("risk_score", {}).get("category", "N/A")
        })
    else:
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

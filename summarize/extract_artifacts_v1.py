import os
import re
import json
import socket
import ipaddress
import requests
from pathlib import Path
from time import sleep
from dotenv import load_dotenv
from colorama import Fore, Style, init

# === INIT ===
init(autoreset=True)
load_dotenv()

# === CONFIGURATION ===
APIKEY = os.getenv("APIVOID_API_KEY")
CURRENT_DIR = Path(".")
OUTPUT_FILE = "ipinfo_results.json"
SLEEP_TIME = 1

# === TLD WHITELIST ===
VALID_TLDS = {
    'com','org','net','edu','gov','mil','co','io','ai','info','biz','us','uk','de','fr','ca',
    'au','cn','jp','kr','es','br','tv','me','xyz','site','tech','dev','app','online','store',
    'pro','name','club','live','cloud','digital','media','today','news','services','solutions',
    'support','systems','world','zone','in','it','ru'
}

# === REGEX ===
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

# === UTILITIES ===
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def is_valid_domain(domain):
    domain = domain.strip().lower()
    if domain.count('.') < 1:
        return False
    parts = domain.split('.')
    if any(p.isdigit() for p in parts[:-1]):
        return False
    if any(p[0].isupper() for p in domain.split('.')):
        return False
    tld = parts[-1]
    return tld in VALID_TLDS

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def query_ipapi(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.ok:
            data = r.json()
            return {
                "country": data.get("country", "N/A"),
                "region": data.get("regionName", "N/A"),
                "city": data.get("city", "N/A"),
                "asn": data.get("as", "N/A"),
                "isp": data.get("isp", "N/A"),
                "org": data.get("org", "N/A")
            }
    except Exception as e:
        return {"error": str(e)}
    return {"error": "Lookup failed"}

def query_apivoid(ip):
    if not APIKEY:
        return {"threat_score": "N/A", "error": "No APIVOID_API_KEY"}
    try:
        url = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={APIKEY}&ip={ip}"
        r = requests.get(url)
        if r.ok:
            data = r.json().get("data", {}).get("report", {})
            score = data.get("risk_analysis", {}).get("risk_score", {}).get("result", 0)
            category = data.get("risk_analysis", {}).get("risk_score_result", {}).get("category", "N/A")
            return {"threat_score": score, "threat_category": category}
        else:
            return {"threat_score": "N/A", "error": f"{r.status_code} - {r.text}"}
    except Exception as e:
        return {"threat_score": "N/A", "error": str(e)}

def colorize_score(score):
    if isinstance(score, int):
        if score == 0:
            return Fore.GREEN
        elif score == 100:
            return Fore.RED
        else:
            return Fore.YELLOW
    return Fore.WHITE

# === MAIN PROCESS ===
all_ips = set()
all_domains = set()
results = []

# Extract from all .txt files in current folder
for file in CURRENT_DIR.glob("*.txt"):
    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        all_ips.update(re.findall(IP_REGEX, content))
        all_domains.update(re.findall(DOMAIN_REGEX, content))

public_ips = {ip for ip in all_ips if is_public_ip(ip)}
valid_domains = {d for d in all_domains if not re.match(IP_REGEX, d) and is_valid_domain(d)}

print(f" Found {len(public_ips)} unique public IPs")
print(f" Found {len(valid_domains)} valid domains")

# === Process IPs ===
for ip in sorted(public_ips):
    geo = query_ipapi(ip)
    av = query_apivoid(ip)
    score = av.get("threat_score", 0)
    color = colorize_score(score)
    print(f"{color}[IP] {ip} → Score: {score}, Country: {geo.get('country')} / ASN: {geo.get('asn')}{Style.RESET_ALL}")
    results.append({
        "ip": ip,
        "source": "direct",
        **geo,
        **av
    })
    sleep(SLEEP_TIME)

# === Process Domains ===
for domain in sorted(valid_domains):
    resolved_ip = resolve_domain(domain)
    if resolved_ip and is_public_ip(resolved_ip):
        geo = query_ipapi(resolved_ip)
        av = query_apivoid(resolved_ip)
        score = av.get("threat_score", 0)
        color = colorize_score(score)
        print(f"{color}[DOMAIN] {domain} → {resolved_ip} → Score: {score}, Country: {geo.get('country')} / ASN: {geo.get('asn')}{Style.RESET_ALL}")
        results.append({
            "domain": domain,
            "ip": resolved_ip,
            "source": "domain",
            **geo,
            **av
        })
        sleep(SLEEP_TIME)
    else:
        print(f"{Fore.LIGHTBLACK_EX}[DOMAIN] {domain} → Unresolved or private IP{Style.RESET_ALL}")
        results.append({
            "domain": domain,
            "error": "Could not resolve or not public IP"
        })

# === Save Output ===
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print(f"\n Results saved to {OUTPUT_FILE}")

import os, re, json, base64, hashlib, ipaddress, requests
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Dummy:  # fallback
        def __getattr__(self, attr): return ''
    Fore = Style = Dummy()

DECODED_DIR = Path("./decoded")
DECODED_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = "decoded_analysis_results.json"

SUSPICIOUS_ASNS = [
    "DigitalOcean", "PhotonVPS", "Linode", "Vultr", "Huawei", "Baehost", "Hetzner",
    "OVH", "esecuredata.com", "webhuset.no", "mirohost.net", "estoxy.com",
    "vietnex.nv", "XSServer GmbH", "Tencent", "Hostinger"
]

IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
HEX_SHELLCODE_REGEX = r'(?:\\x[0-9a-fA-F]{2}){4,}'
RAW_HEX_BLOB_REGEX = r'\b(?:[0-9a-fA-F]{8,})\b'
BASE64_REGEX = r'(?<![\w+/=])(?:[A-Za-z0-9+/]{20,}={0,2})(?![\w+/=])'
ASM_KEYWORDS = ['mov', 'jmp', 'call', 'xor', 'push', 'pop', 'ret', 'int', 'syscall']

HEURISTIC_PATTERNS = {
    "password_grabber": [r'(?i)grab(pass(word)?|cred|token)', r'(?i)chrome.*(login|password)', r'(?i)get(stored)?(password|credentials)'],
    "keylogger": [r'(?i)GetAsyncKeyState', r'(?i)keylogger', r'(?i)GetWindowText', r'(?i)keyboard hook']
}

MEMORY_HOOK_PATTERNS = [
    r'(?i)SetWindowsHookEx', r'(?i)GetAsyncKeyState', r'(?i)CreateRemoteThread',
    r'(?i)VirtualAlloc(Ex)?', r'(?i)WriteProcessMemory', r'(?i)ReadProcessMemory'
]

def is_public_ip(ip):
    try: return ipaddress.ip_address(ip).is_global
    except: return False

def get_ip_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        asn = res.get("as", "")
        country = res.get("country", "")
        flagged = any(s.lower() in asn.lower() for s in SUSPICIOUS_ASNS)
        score = max(50, 100 if flagged else 0) if flagged else 0
        return {"ip": ip, "asn": asn, "country": country, "threat_score": score, "is_flagged": flagged}
    except Exception: return {"ip": ip, "error": "lookup_failed"}

def extract_intel(text):
    ips = [ip for ip in re.findall(IP_REGEX, text) if is_public_ip(ip)]
    domains = re.findall(DOMAIN_REGEX, text)
    return {"ips": list(set(ips)), "domains": list(set(domains))}

def detect_shellcode(text, filename):
    results, memory_hooks, decoded_b64 = [], [], []
    heuristics = []

    if re.search(HEX_SHELLCODE_REGEX, text): results.append("hex_shellcode")
    if re.search(RAW_HEX_BLOB_REGEX, text): results.append("raw_hex_blob")
    if any(k in text.lower() for k in ASM_KEYWORDS): results.append("assembly")

    for tag, pats in HEURISTIC_PATTERNS.items():
        for pat in pats:
            if re.search(pat, text): heuristics.append(tag); break
    for pat in MEMORY_HOOK_PATTERNS:
        if re.search(pat, text): memory_hooks.append(pat.strip("(?i)"))

    for b64 in re.findall(BASE64_REGEX, text):
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            if decoded.strip():
                h = hashlib.sha256(decoded.encode()).hexdigest()
                fpath = DECODED_DIR / f"{filename}_{h[:8]}.txt"
                fpath.write_text(decoded, encoding="utf-8")
                print(f"{Fore.CYAN}[DECODED BASE64] {fpath}{Style.RESET_ALL}")
                intel = extract_intel(decoded)
                decoded_b64.append({"sha256": h, "file": str(fpath), "sample": decoded[:100], "intel": intel})
                for pat in MEMORY_HOOK_PATTERNS:
                    if re.search(pat, decoded): memory_hooks.append(pat.strip("(?i)"))
        except: continue

    if results or heuristics or memory_hooks or decoded_b64:
        print(f"{Fore.MAGENTA}[SHELLCODE] {filename}: {', '.join(results + heuristics)}{Style.RESET_ALL}")
        if memory_hooks:
            print(f"{Fore.RED}[MEMORY HOOKS] {filename}: {', '.join(set(memory_hooks))}{Style.RESET_ALL}")
        return {
            "file": filename,
            "shellcode_detected": results,
            "heuristic_flags": heuristics,
            "memory_api_hooks": list(set(memory_hooks)),
            "base64_decoded": decoded_b64
        }
    return None

# Main
final = []
for file in Path(".").glob("*.txt"):
    text = file.read_text(encoding="utf-8", errors="ignore")
    result = detect_shellcode(text, file.name)
    if not result: continue

    all_ips = set()
    for entry in result["base64_decoded"]:
        all_ips.update(entry["intel"]["ips"])
    if not all_ips:
        all_ips.update(extract_intel(text)["ips"])

    enriched = [get_ip_info(ip) for ip in all_ips]
    for ipinfo in enriched:
        score = ipinfo.get("threat_score", 0)
        color = Fore.GREEN if score == 0 else (Fore.YELLOW if score < 100 else Fore.RED)
        print(f"{color}[IP] {ipinfo['ip']} - {ipinfo.get('asn', '?')} - {ipinfo.get('country', '?')} Score: {score}{Style.RESET_ALL}")
    result["ip_enrichment"] = enriched
    final.append(result)

Path(OUTPUT_FILE).write_text(json.dumps(final, indent=2))
print(f"\n Results saved to {OUTPUT_FILE}")

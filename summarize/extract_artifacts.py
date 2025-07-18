import os, re, json, base64, hashlib, ipaddress, requests, subprocess
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Dummy:  # fallback
        def __getattr__(self, attr): return ''
    Fore = Style = Dummy()

DECODED_DIR = Path("./decoded")
SCRIPTS_DIR = Path("./decoded_scripts")
DECODED_DIR.mkdir(exist_ok=True)
SCRIPTS_DIR.mkdir(exist_ok=True)
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
SCRIPT_SIGS = {
    "powershell": r"(?i)powershell|Invoke-|EncodedCommand",
    "js": r"(?i)\bfunction\b|\beval\b|XMLHttpRequest|document\.",
    "batch": r"(?i)@echo off|cmd\.exe|start\b",
    "vbs": r"(?i)CreateObject|\.Run|WScript\.Shell",
    "vba": r"(?i)Sub AutoOpen|Document_Open|Shell"
}

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

def analyze_binary(filepath):
    result = {"lief": None, "capa": None, "floss": None}
    try:
        import lief
        binobj = lief.parse(str(filepath))
        result["lief"] = {
            "entrypoint": hex(binobj.entrypoint),
            "sections": [s.name for s in binobj.sections]
        }
    except: result["lief"] = "failed"

    try:
        capa_output = subprocess.check_output(["capa", str(filepath)], stderr=subprocess.DEVNULL, timeout=15, text=True)
        result["capa"] = capa_output[:500]
    except: result["capa"] = "failed"

    try:
        floss_output = subprocess.check_output(["floss", str(filepath)], stderr=subprocess.DEVNULL, timeout=10, text=True)
        result["floss"] = floss_output[:300]
    except: result["floss"] = "failed"

    return result

def detect_script(text, filename):
    found = []
    for tag, sig in SCRIPT_SIGS.items():
        if re.search(sig, text):
            h = hashlib.sha256(text.encode()).hexdigest()
            fpath = SCRIPTS_DIR / f"{filename}_{tag}_{h[:8]}.txt"
            fpath.write_text(text, encoding="utf-8")
            print(f"{Fore.YELLOW}[SCRIPT] {tag.upper()} in {filename} → {fpath}")
            found.append({"type": tag, "file": str(fpath)})
    return found

def detect_shellcode(text, filename):
    results, memory_hooks, decoded_b64 = [], [], []
    heuristics, scripts = [], []

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
                print(f"{Fore.CYAN}[DECODED BASE64] {fpath}")
                intel = extract_intel(decoded)
                script_hits = detect_script(decoded, filename)
                bin_analysis = analyze_binary(fpath) if b'\x' in decoded.encode() else None
                decoded_b64.append({
                    "sha256": h, "sample": decoded[:100], "file": str(fpath),
                    "intel": intel, "scripts": script_hits, "binary_analysis": bin_analysis
                })
                for pat in MEMORY_HOOK_PATTERNS:
                    if re.search(pat, decoded): memory_hooks.append(pat.strip("(?i)"))
        except: continue

    if results or heuristics or memory_hooks or decoded_b64:
        print(f"{Fore.MAGENTA}[SHELLCODE] {filename}: {', '.join(results + heuristics)}")
        if memory_hooks:
            print(f"{Fore.RED}[MEMORY HOOKS] {filename}: {', '.join(set(memory_hooks))}")
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

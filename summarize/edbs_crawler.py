import os
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from transformers import pipeline
from tqdm import tqdm

# -------------- CONFIG ----------------
BASE_URL = "https://site.com"
COOKIE_NAME = "svSession"
COOKIE_VALUE = "PASTE_YOUR_COOKIE_HERE"  # <--- Replace this with your real svSession value
OUTPUT_DIR = "edbs_content"
MEDIA_DIR = os.path.join(OUTPUT_DIR, "media")
MAX_PAGES = 20  # Maximum number of pages to crawl
HEADERS = {"User-Agent": "Mozilla/5.0"}
CHUNK_SIZE = 1000  # Characters per summarization chunk
# --------------------------------------

visited = set()
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

def is_internal_link(href):
    return href and BASE_URL in urljoin(BASE_URL, href)

def clean_filename(url):
    path = urlparse(url).path.strip("/")
    return re.sub(r'[^\w\-_.]', '_', path or "index")

def save_text(content, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def download_media(session, tag, attr):
    url = tag.get(attr)
    if not url:
        return
    full_url = urljoin(BASE_URL, url)
    filename = os.path.join(MEDIA_DIR, clean_filename(full_url))
    try:
        r = session.get(full_url, stream=True, timeout=10)
        if r.status_code == 200:
            with open(filename, 'wb') as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
    except:
        print(f"⚠️ Failed to download media: {full_url}")

def summarize_text(text):
    chunks = [text[i:i+CHUNK_SIZE] for i in range(0, len(text), CHUNK_SIZE)]
    summaries = []
    for i, chunk in enumerate(chunks):
        result = summarizer(chunk, max_length=200, min_length=60, do_sample=False)
        summaries.append(result[0]['summary_text'])
    return "\n\n".join(summaries)

def scrape_page(session, url):
    if url in visited or len(visited) >= MAX_PAGES:
        return
    visited.add(url)

    print(f"🔍 Scraping: {url}")
    try:
        r = session.get(url, timeout=10)
    except:
        print("❌ Failed to load page.")
        return

    if r.status_code != 200:
        print(f"❌ Error {r.status_code} on {url}")
        return

    soup = BeautifulSoup(r.text, "html.parser")
    text = soup.get_text(separator="\n", strip=True)

    # Save raw text
    page_id = clean_filename(url)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(MEDIA_DIR, exist_ok=True)
    text_path = os.path.join(OUTPUT_DIR, f"{page_id}.txt")
    save_text(text, text_path)

    # Summarize and save summary
    print(f"🧠 Summarizing: {url}")
    summary = summarize_text(text)
    summary_path = os.path.join(OUTPUT_DIR, f"{page_id}_summary.txt")
    save_text(summary, summary_path)

    # Download media
    for tag in soup.find_all(["img", "video", "source", "a"]):
        if tag.name == "a" and not re.search(r"\.(pdf|mp4|mov|zip|docx?)$", tag.get("href", ""), re.I):
            continue
        download_media(session, tag, "src" if tag.name != "a" else "href")

    # Crawl internal links
    for a in soup.find_all("a", href=True):
        link = urljoin(BASE_URL, a["href"])
        if is_internal_link(link) and link not in visited:
            scrape_page(session, link)

def main():
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.set(COOKIE_NAME, COOKIE_VALUE, domain=urlparse(BASE_URL).netloc)

    print("🚀 Starting crawl of:", BASE_URL)
    scrape_page(session, BASE_URL)

    print("\n✅ Done. All data saved in:", OUTPUT_DIR)

if __name__ == "__main__":
    main()

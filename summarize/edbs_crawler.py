from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
import time
import os

# --- CONFIG ---
BASE_URL = "https://site.com"
TARGET_PAGE = "https://site.com/protected-page"  # Change if needed
PASSWORD = "X"
OUTPUT_FILE = "edbs_rendered_text.txt"
WAIT_TIME = 10  # seconds
# --------------

options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-gpu")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

try:
    # Visit homepage or login page
    driver.get(BASE_URL)
    time.sleep(3)

    # Locate password input (adjust selector if needed)
    try:
        password_input = driver.find_element(By.XPATH, "//input[@type='password']")
        password_input.send_keys(PASSWORD)
        password_input.submit()
        print("🔐 Password submitted")
        time.sleep(WAIT_TIME)
    except Exception as e:
        print("⚠️ Couldn't find password field (might already be logged in?):", e)

    # Visit target page
    driver.get(TARGET_PAGE)
    time.sleep(WAIT_TIME)

    # Extract visible text from the page
    page_text = driver.find_element(By.TAG_NAME, "body").text
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(page_text)

    print(f"✅ Page text saved to {OUTPUT_FILE}")
    print("Preview:\n" + "-"*40)
    print(page_text[:1000], "...\n")

finally:
    driver.quit()

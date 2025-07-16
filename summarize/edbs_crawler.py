from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import time

# --- Your svSession cookie here ---
svsession_value = "YOUR_SVSESSION_VALUE_HERE"
base_url = "https://edbsportal.com"
output_file = "edbs_loggedin_text.txt"

# Set up browser
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-gpu")
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

try:
    # Load the site once to set the cookie domain
    driver.get(base_url)
    time.sleep(2)

    # Inject the svSession cookie
    driver.add_cookie({
        "name": "svSession",
        "value": svsession_value,
        "domain": ".edbsportal.com",  # note the leading dot
        "path": "/"
    })

    print(" Cookie injected. Reloading site...")

    # Reload the site (you should now be authenticated)
    driver.get(base_url)
    time.sleep(5)

    # Grab visible text
    page_text = driver.find_element(By.TAG_NAME, "body").text
    print("Page content:\n", page_text[:1000])
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(page_text)

finally:
    driver.quit()

import os
import re
import time
from typing import Optional
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

DEFAULT_URL = os.getenv("SMN_URL", "https://www.smn.gob.ar/")
DEFAULT_OUTPUT_FILE = "token"


def extract_token_from_source(source: str) -> Optional[str]:
    m = re.search(
        r"localStorage\.setItem\(\s*['\"]token['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        source,
    )
    if m:
        return m.group(1)

    m = re.search(r"localStorage\.token\s*=\s*['\"]([^'\"]+)['\"]", source)
    if m:
        return m.group(1)

    return None


def make_chrome_options(headless: bool = True) -> Options:
    opts = Options()
    if headless:
        try:
            opts.add_argument("--headless=new")
        except Exception:
            opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/118.0.5993.90 Safari/537.36"
    )
    return opts


def get_token(
    url: str = DEFAULT_URL,
    headless: bool = True,
    wait_seconds: int = 8,
    driver_wait_timeout: int = 20,
    chrome_driver_path: Optional[str] = None,
) -> Optional[str]:

    options = make_chrome_options(headless=headless)

    driver = None
    try:
        if chrome_driver_path:
            driver = webdriver.Chrome(executable_path=chrome_driver_path, options=options)
        else:
            driver = webdriver.Chrome(options=options)

        # load page
        driver.get(url)

        if wait_seconds:
            time.sleep(wait_seconds)

        try:
            WebDriverWait(driver, driver_wait_timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except Exception:
            pass

        token = None
        try:
            token = driver.execute_script("return window.localStorage.getItem('token');")
        except Exception:
            token = None

        # fallback to searching page source
        if not token:
            token = extract_token_from_source(driver.page_source)

        return token

    except Exception as ex:
        return None

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def refresh_token(
    output_file: str = DEFAULT_OUTPUT_FILE,
    **get_token_kwargs,
) -> bool:
    token = get_token(**get_token_kwargs)
    if token:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(token)
            return True
        except Exception:
            return False
    return False


if __name__ == "__main__":
    import sys

    url = DEFAULT_URL
    if len(sys.argv) > 1:
        url = sys.argv[1]

    print(f"Loading URL {url}")
    token = get_token(headless=True)
    if token:
        print(f"\n[+] Token found:\n{token}\n")
        try:
            with open(DEFAULT_OUTPUT_FILE, "w", encoding="utf-8") as fh:
                fh.write(token)
            print(f"[+] Saved to {DEFAULT_OUTPUT_FILE}")
        except Exception as e:
            print("[!] Failed to save token:", e)
    else:
        print("[!] No token found in localStorage or page source.")

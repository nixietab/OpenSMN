import os
import re
import time
from typing import Optional
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
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
        opts.add_argument("--headless=new")

    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--start-maximized")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--disable-notifications")

    opts.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )

    opts.add_argument("--disable-infobars")
    opts.add_argument("--disable-web-security")
    opts.add_argument("--disable-features=IsolateOrigins,site-per-process")

    prefs = {
        "profile.default_content_setting_values.notifications": 2,
        "credentials_enable_service": False,
        "profile.password_manager_enabled": False,
    }
    opts.add_experimental_option("prefs", prefs)

    return opts

def inject_stealth_scripts(driver):
    stealth_js = """
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined
    });

    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5]
    });

    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en']
    });

    window.chrome = {
        runtime: {}
    };

    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
    );
    """

    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": stealth_js},
        )
    except Exception:
        pass

def get_token(
    url: str = DEFAULT_URL,
    headless: bool = True,
    wait_seconds: int = 15,
    driver_wait_timeout: int = 30,
    chrome_driver_path: Optional[str] = None,
) -> Optional[str]:
    options = make_chrome_options(headless=headless)
    driver = None

    try:
        if chrome_driver_path:
            service = Service(executable_path=chrome_driver_path)
            driver = webdriver.Chrome(service=service, options=options)
        else:
            driver = webdriver.Chrome(options=options)

        inject_stealth_scripts(driver)

        print(f"[*] Loading URL: {url}")
        driver.get(url)

        print(f"[*] Waiting {wait_seconds}s for page to load and Cloudflare challenge...")
        time.sleep(wait_seconds)

        page_source = driver.page_source.lower()
        if "checking your browser" in page_source or "cloudflare" in page_source:
            print("[*] Cloudflare challenge detected, waiting additional time...")
            time.sleep(10)

        try:
            WebDriverWait(driver, driver_wait_timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            print("[+] Page body loaded")
        except Exception as e:
            print(f"[!] Timeout waiting for body: {e}")

        token = None
        try:
            token = driver.execute_script(
                "return window.localStorage.getItem('token');"
            )
            if token:
                print("[+] Token found in localStorage")
        except Exception as e:
            print(f"[!] Error accessing localStorage: {e}")
            token = None

        if not token:
            print("[*] Searching for token in page source...")
            token = extract_token_from_source(driver.page_source)
            if token:
                print("[+] Token found in page source")

        if not token:
            try:
                with open("debug_page_source.html", "w", encoding="utf-8") as f:
                    f.write(driver.page_source)
                print("[!] No token found. Page source saved to debug_page_source.html")
            except Exception:
                pass

        return token

    except Exception as ex:
        print(f"[!] Error: {ex}")
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

    print(f"[*] Starting token extraction from {url}")
    token = get_token(url=url, headless=True, wait_seconds=15)

    if token:
        print(f"\n[+] Token found:\n{token}\n")
        try:
            with open(DEFAULT_OUTPUT_FILE, "w", encoding="utf-8") as fh:
                fh.write(token)
            print(f"[+] Saved to {DEFAULT_OUTPUT_FILE}")
        except Exception as e:
            print(f"[!] Failed to save token: {e}")
    else:
        print("[!] No token found in localStorage or page source.")
        print("[*] Check debug_page_source.html for more details")

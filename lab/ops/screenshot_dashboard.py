"""One-off headless screenshot of the real Wazuh dashboard, for the M3 submission.
Uses Playwright with ignore_https_errors - this is our own localhost-only lab deployment, not a
real site, so bypassing the self-signed-cert warning here is reasonable automation, not a general
security bypass.

  python lab/ops/screenshot_dashboard.py
"""
from __future__ import annotations

import os
import time

from playwright.sync_api import sync_playwright

URL_LOGIN = "https://localhost/app/login"
URL_DASHBOARD = "https://localhost/app/dashboards#/view/railsoc_m3_dashboard"
USERNAME = "admin"
# Set WAZUH_INDEXER_PASSWORD in your shell before running this - never hardcode the real
# credential here (it gets committed). Defaults to the upstream wazuh-docker demo password so
# this still works out of the box against an unrotated deployment.
PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")


def main() -> int:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(ignore_https_errors=True, viewport={"width": 1600, "height": 1000})

        page.goto(URL_LOGIN, wait_until="networkidle", timeout=60000)
        page.screenshot(path="lab/data/raw/screenshot_00_login.png")

        page.fill('[data-test-subj="user-name"]', USERNAME)
        page.fill('[data-test-subj="password"]', PASSWORD)
        page.click('[data-test-subj="submit"]')
        page.wait_for_load_state("networkidle", timeout=60000)
        time.sleep(2)
        page.screenshot(path="lab/data/raw/screenshot_01_after_login.png")

        page.goto(URL_DASHBOARD, wait_until="networkidle", timeout=60000)
        time.sleep(4)
        page.screenshot(path="lab/data/raw/screenshot_02_dashboard.png", full_page=True)

        browser.close()
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

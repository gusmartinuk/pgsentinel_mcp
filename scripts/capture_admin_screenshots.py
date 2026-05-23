from __future__ import annotations

import argparse
import os
from pathlib import Path

from playwright.sync_api import sync_playwright


def _env_or_value(value: str | None, env_name: str) -> str:
    if value:
        return value
    env_value = os.environ.get(env_name, "").strip()
    if env_value:
        return env_value
    raise SystemExit(f"missing required value: --{env_name.lower().replace('_', '-')} or {env_name}")


def _capture(page, base_url: str, path: str, output: Path) -> None:
    page.goto(f"{base_url}{path}", wait_until="networkidle")
    if path != "/admin/login" and "/admin/login" in page.url:
        raise RuntimeError(f"redirected to login while capturing {path}; auth/session failed")
    # Sanitize potentially sensitive values in UI before screenshot.
    page.evaluate(
        """() => {
            const sensitivePatterns = [
              /prod|production|staging|vps|db|postgres|server|host|ip/i,
              /\\d+\\.\\d+\\.\\d+\\.\\d+/,
            ];
            const maskText = (el) => {
              if (!el || !el.textContent) return;
              const t = el.textContent.trim();
              if (!t) return;
              if (sensitivePatterns.some((re) => re.test(t)) || t.length > 18) {
                el.textContent = "redacted";
              }
            };
            document.querySelectorAll("td, th, .badge, .meta-value, pre, code").forEach(maskText);
        }"""
    )
    page.set_viewport_size({"width": 1600, "height": 1000})
    page.screenshot(path=str(output), full_page=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture PgSentinel admin screenshots with Playwright.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8088", help="PgSentinel base URL")
    parser.add_argument("--password", default=None, help="Master password (or set PGSENTINEL_SCREENSHOT_PASSWORD)")
    parser.add_argument("--vault-name", default=None, help="Optional vault name for multi-vault login selection")
    parser.add_argument("--out-dir", default="docs/images", help="Output directory for screenshots")
    parser.add_argument("--headed", action="store_true", help="Run browser in headed mode")
    parser.add_argument("--debug-dir", default="docs/images/debug", help="Directory for failure debug artifacts")
    args = parser.parse_args()

    password = _env_or_value(args.password, "PGSENTINEL_SCREENSHOT_PASSWORD")
    base_url = args.base_url.rstrip("/")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    debug_dir = Path(args.debug_dir)
    debug_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed)
        page = browser.new_page()

        page.goto(f"{base_url}/admin/login", wait_until="networkidle")
        if args.vault_name:
            select = page.locator("select[name='name']")
            if select.count() > 0:
                select.select_option(args.vault_name)
                page.locator("button:has-text('Use Selected Vault')").click()
                page.wait_for_load_state("networkidle")

        page.fill("input[name='master_password']", password)
        page.click("form[action='/admin/login'] button[type='submit']")
        page.wait_for_load_state("networkidle")
        if "/admin/login" in page.url:
            page.screenshot(path=str(debug_dir / "login_failed.png"), full_page=True)
            (debug_dir / "login_failed.html").write_text(page.content(), encoding="utf-8")
            error_text = ""
            try:
                error = page.locator(".error")
                if error.count() > 0:
                    error_text = error.first.inner_text().strip()
            except Exception:
                pass
            raise RuntimeError(
                f"login failed (still on /admin/login); check password or selected vault. "
                f"url={page.url} error={error_text or 'N/A'} debug={debug_dir}"
            )

        _capture(page, base_url, "/admin/login", out_dir / "login.png")
        _capture(page, base_url, "/admin/dashboard", out_dir / "dashboard.png")
        _capture(page, base_url, "/admin/servers", out_dir / "servers.png")
        _capture(page, base_url, "/admin/postgres", out_dir / "postgres.png")
        _capture(page, base_url, "/admin/monitoring", out_dir / "monitoring.png")
        _capture(page, base_url, "/admin/agent", out_dir / "agent.png")
        _capture(page, base_url, "/admin/settings", out_dir / "settings.png")
        _capture(page, base_url, "/admin/audit", out_dir / "audit.png")
        _capture(page, base_url, "/admin/vaults", out_dir / "vaults.png")

        browser.close()

    print(f"screenshots written to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

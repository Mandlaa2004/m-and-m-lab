"""Browser-based UI regression tests. Skipped automatically if Playwright or its
browser binaries are not installed (see requirements-dev.txt + `playwright install`)."""
import socket
import threading

import pytest

playwright_sync_api = pytest.importorskip("playwright.sync_api")
sync_playwright = playwright_sync_api.sync_playwright

import app as app_module
from werkzeug.serving import make_server


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def live_server(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "DATABASE", tmp_path / "ui-test.db")
    monkeypatch.setattr(app_module, "BACKUP_DIR", tmp_path / "backups")
    app_module.initialize_database()
    port = _free_port()
    server = make_server("127.0.0.1", port, app_module.app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def browser_page():
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            yield page
            browser.close()
    except Exception as error:  # noqa: BLE001 - browser binaries may be absent
        pytest.skip(f"Playwright browser unavailable: {error}")


def _login(page, base_url, username, password):
    page.goto(f"{base_url}/login")
    page.fill("[name='username']", username)
    page.fill("[name='password']", password)
    page.click("button[type='submit']")
    page.wait_for_url(f"{base_url}/")


def test_login_reaches_dashboard(live_server, browser_page):
    _login(browser_page, live_server, "analyst", "analyst123")
    assert browser_page.locator("#total-events").count() == 1


def test_ip_inspection_shows_threat_score(live_server, browser_page):
    with app_module.app.app_context():
        app_module.record_event(
            "Threat signal", "185.220.101.14", "CRITICAL", "Known hostile activity")
    _login(browser_page, live_server, "analyst", "analyst123")
    browser_page.fill("#ip-input", "185.220.101.14")
    browser_page.click("#ip-button")
    browser_page.wait_for_selector("#ip-result .ip-intel-head")
    assert "/100" in browser_page.locator("#ip-result").inner_text()


def test_incident_stage_can_be_advanced(live_server, browser_page):
    _login(browser_page, live_server, "analyst", "analyst123")
    browser_page.fill("#incident-title", "Browser-driven case")
    browser_page.click("#incident-button")
    browser_page.wait_for_selector(".incident-stage")
    browser_page.select_option(".incident-stage >> nth=0", "CONTAIN")
    browser_page.click(".row-action >> nth=0")
    browser_page.wait_for_timeout(300)
    assert browser_page.locator(".incident-stage >> nth=0").input_value() == "CONTAIN"


def test_viewer_role_hides_admin_controls(live_server, browser_page):
    _login(browser_page, live_server, "viewer", "viewer123")
    assert browser_page.locator("#user-form").count() == 0 or not browser_page.locator(
        "#users-list .user-item").count()

"""Capture the VS Code workbench through Chrome DevTools (Electron's remote debugging port).
Usage: grab.py PORT OUT [W H]   (W x H CSS pixels, captured at 2x)"""
import base64
import sys
from playwright.sync_api import sync_playwright
port, out = sys.argv[1], sys.argv[2]
w, h = (int(sys.argv[3]), int(sys.argv[4])) if len(sys.argv) > 4 else (1400, 900)
with sync_playwright() as p:
    b = p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
    pg = next(pg for c in b.contexts for pg in c.pages if "workbench" in pg.url)
    cdp = pg.context.new_cdp_session(pg)
    cdp.send("Emulation.setDeviceMetricsOverride", {"width": w, "height": h, "deviceScaleFactor": 2, "mobile": False})
    pg.wait_for_timeout(1500)
    for _ in range(3):                      # first-run dialogs
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(400)
    shot = cdp.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
    open(out, "wb").write(base64.b64decode(shot["data"]))
    print("captured", w, h)

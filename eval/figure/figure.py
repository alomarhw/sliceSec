"""Fig. 2 on cfingerd 1.4.3 (CVE-2001-0609), the ident-reply path: one real VS Code window with sliceSec installed from its VSIX, driven like
a user (keys, palette, mouse). Launch first:
  code --user-data-dir ud --extensions-dir exts --new-window --remote-debugging-port=9334 ../cve/vulnerable/cfingerd-1.4.3
(ud holds User/settings.json and User/keybindings.json from this folder; exts holds the sliceSec VSIX.)
Usage: figure.py OUT.png"""
import json, sys
from cdp import VS
W, H, Z = 2100, 1090, 1.0954
SIDEBAR, MAIN_END, PANEL = 365, 1225, 205
U = lambda css: css / Z
SET = "ud/User/settings.json"
with VS() as v:
    pg = v.pg
    v.cdp.send("Emulation.setDeviceMetricsOverride", {"width": W, "height": H, "deviceScaleFactor": 2, "mobile": False})
    v.wait(1500)
    for _ in range(2): v.key("Escape")
    v.palette("View: Close All Editor Groups"); v.wait(800)
    v.palette("View: Two Rows Right Editor Layout")
    v.key("Meta+1"); v.quick_open("src/rfc1413.c")
    v.key("Meta+2"); v.quick_open("src/main.c")
    v.key("Meta+3"); v.quick_open("src/main.c")
    v.wait(6000)
    v.key("Meta+Shift+M"); v.wait(800)
    hdr = pg.locator(".part.sidebar .pane-header").filter(has_text="Slice and Taint Path").first
    if hdr.get_attribute("aria-expanded") != "true": hdr.click(); v.wait(500)
    ex = pg.locator(".part.sidebar .pane-header").filter(has_text="cfingerd").first
    if ex.count() and ex.get_attribute("aria-expanded") == "true": ex.click(); v.wait(400)
    def sash(kind, near):
        best = None
        for s in pg.locator(f".monaco-sash.{kind}").all():
            bb = s.bounding_box()
            if not bb or bb["width"] == 0 or bb["height"] == 0 or "disabled" in (s.get_attribute("class") or ""): continue
            c = bb["x"] + bb["width"] / 2 if kind == "vertical" else bb["y"] + bb["height"] / 2
            if best is None or abs(c - near) < best[0]: best = (abs(c - near), bb)
        return best[1]
    def drag(kind, near, to, along):
        bb = sash(kind, near)
        if kind == "vertical": x0, y0, x1, y1 = bb["x"] + bb["width"] / 2, along, to, along
        else: x0, y0, x1, y1 = along, bb["y"] + bb["height"] / 2, along, to
        pg.mouse.move(x0, y0); pg.mouse.down(); pg.mouse.move(x1, y1, steps=12); pg.mouse.up(); v.wait(500)
    sb = pg.locator(".part.sidebar").bounding_box()
    drag("vertical", sb["x"] + sb["width"], U(48 + SIDEBAR), U(300))
    pn = pg.locator(".part.panel").bounding_box()
    drag("horizontal", pn["y"], U(H - 22 - PANEL), U(1000))
    eds = pg.locator(".part.editor .editor-group-container")
    drag("vertical", eds.nth(1).bounding_box()["x"], U(MAIN_END), U(300))
    # each editor: go to a line, then scroll so that `top` is the first line
    d = json.load(open(SET)); d["editor.scrollbar.vertical"] = "auto"; json.dump(d, open(SET, "w"), indent=1); v.wait(1500)
    for g, line, top in ((0, 95, 79), (1, 210, 203), (2, 250, 245)):
        v.key(f"Meta+{g + 1}"); v.key("Control+G"); pg.keyboard.type(str(line)); v.key("Enter"); v.wait(500)
        ed = eds.nth(g); fr = ed.locator(".overflow-guard").first.bounding_box()
        v.key("Meta+ArrowUp"); v.wait(300)                              # scrollTop 0: no partial line left over
        for _ in range(top - 1): pg.keyboard.press("Control+Alt+Shift+J", delay=5)
        v.wait(400)
        for _ in range(60):
            ys = {t.inner_text().strip(): t.bounding_box()["y"] for t in ed.locator(".line-numbers").all()}
            y = ys.get(str(top))
            if y is None: dlt = 1 if min(int(k) for k in ys if k.isdigit()) < top else -1
            else: dlt = y - fr["y"]
            if abs(dlt) < 0.6: break
            pg.keyboard.press("Control+Alt+Shift+J" if dlt > 0 else "Control+Alt+Shift+K"); v.wait(120)
        print("group", g, "top", top, "offset", round(dlt, 2))
    d = json.load(open(SET)); d["editor.scrollbar.vertical"] = "hidden"; json.dump(d, open(SET, "w"), indent=1); v.wait(1500)
    # Show Taint Path on ident_user where line 253 formats it into syslog_str
    b = v.token(2, "username,\u00a0ident_user", "ident_user")
    pg.mouse.click(b["x"] + b["w"] * 0.45, b["y"] + b["h"] / 2); v.wait(400)
    v.palette("sliceSec: Show Taint Path"); v.wait(1500)
    # Problems: filter to CWE-134, findings collapsed to their messages
    f = pg.locator(".part.panel .markers-panel-action-filter input, .part.panel input[placeholder^='Filter']").first
    if f.input_value() != "CWE-134":
        f.focus(); v.key("Meta+A"); pg.keyboard.type("CWE-134"); v.wait(1000)
    for _ in range(3):
        rows = pg.locator('.part.panel .monaco-list-row[aria-level="2"][aria-expanded="true"]')
        if rows.count() == 0: break
        t = rows.first.locator(".monaco-tl-twistie").bounding_box(); pg.mouse.click(t["x"] + t["width"] / 2, t["y"] + t["height"] / 2); v.wait(400)
        for i in range(rows.count()):
            r = pg.locator('.part.panel .monaco-list-row[aria-level="2"][aria-expanded="true"]')
            if r.count() == 0: break
            t = r.first.locator(".monaco-tl-twistie").bounding_box(); pg.mouse.click(t["x"] + t["width"] / 2, t["y"] + t["height"] / 2); v.wait(400)
    # hover over bleah on line 111 (srcPtr points-to set), shown above the line
    b = pg.evaluate("""([g, n, w]) => {
        const ed = [...document.querySelectorAll('.part.editor .editor-group-container')][g];
        const ln = [...ed.querySelectorAll('.line-numbers')].find(e => e.textContent.trim() === String(n));
        const y = ln.getBoundingClientRect().top + 2;
        for (const vl of ed.querySelectorAll('.view-line')) {
          const r0 = vl.getBoundingClientRect(); if (Math.abs(r0.top - ln.getBoundingClientRect().top) > 3) continue;
          const tw = document.createTreeWalker(vl, NodeFilter.SHOW_TEXT); let t;
          while ((t = tw.nextNode())) { const i = t.textContent.indexOf(w); if (i >= 0) {
            const r = document.createRange(); r.setStart(t, i); r.setEnd(t, i + w.length); const b = r.getBoundingClientRect();
            return {x: b.x, y: b.y, w: b.width, h: b.height}; } } }
        return null; }""", [0, 111, "bleah"])
    pg.mouse.move(b["x"] + b["w"] / 2, b["y"] + b["h"] / 2, steps=5); v.wait(1800)
    v.shot(sys.argv[1])

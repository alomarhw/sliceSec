"""Drive a running VS Code (remote debugging port 9334) the way a user would: keys, command palette, mouse."""
import base64, sys, time
from playwright.sync_api import sync_playwright

PORT = 9334

class VS:
    def __enter__(self):
        self.p = sync_playwright().start()
        self.b = self.p.chromium.connect_over_cdp(f"http://127.0.0.1:{PORT}")
        self.pg = next(pg for c in self.b.contexts for pg in c.pages if "workbench" in pg.url)
        self.cdp = self.pg.context.new_cdp_session(self.pg)
        return self
    def __exit__(self, *a):
        self.p.stop()
    def wait(self, ms): self.pg.wait_for_timeout(ms)
    def key(self, k): self.pg.keyboard.press(k); self.wait(250)
    def palette(self, text):
        self.key("Meta+Shift+P"); self.wait(400)
        self.pg.keyboard.type(text, delay=15); self.wait(700); self.key("Enter"); self.wait(800)
    def quick_open(self, name):
        self.key("Meta+P"); self.wait(400); self.pg.keyboard.type(name, delay=15); self.wait(700); self.key("Enter"); self.wait(800)
    def token(self, group, line_text, word, nth=-1):
        """Screen box of `word` (last or nth occurrence) in the visible line containing line_text, in editor group `group` (0-based)."""
        return self.pg.evaluate("""([g, lt, w, nth]) => {
            const eds = [...document.querySelectorAll('.part.editor .editor-group-container')];
            const ed = eds[g]; if (!ed) return null;
            for (const ln of ed.querySelectorAll('.view-line')) {
              if (!ln.textContent.includes(lt)) continue;
              const tw = document.createTreeWalker(ln, NodeFilter.SHOW_TEXT); let n; const hits = [];
              while ((n = tw.nextNode())) { let i = -1; while ((i = n.textContent.indexOf(w, i + 1)) >= 0) {
                  const before = n.textContent[i - 1] || ' ', after = n.textContent[i + w.length] || ' ';
                  if (!/\\w/.test(before) && !/\\w/.test(after)) hits.push([n, i]); } }
              const h = hits.at(nth); if (!h) return null;
              const r = document.createRange(); r.setStart(h[0], h[1]); r.setEnd(h[0], h[1] + w.length);
              const b = r.getBoundingClientRect(); return {x: b.x, y: b.y, w: b.width, h: b.height}; }
            return null; }""", [group, line_text, word, nth])
    def click_word(self, group, line_text, word, nth=-1):
        b = self.token(group, line_text, word, nth)
        assert b, (group, line_text, word)
        self.pg.mouse.click(b["x"] + b["w"] * 0.45, b["y"] + b["h"] / 2); self.wait(400)
        return b
    def shot(self, out):
        s = self.cdp.send("Page.captureScreenshot", {"format": "png"})
        open(out, "wb").write(base64.b64decode(s["data"]))

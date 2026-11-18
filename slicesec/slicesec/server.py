"""Editor server: JSON-RPC 2.0, one JSON object per line on stdin and stdout.

Methods
  initialize {root, maxHops?}            -> {versions, files, profiles, findings, seconds, skipped}
  analyze    {}                          -> {findings, seconds, skipped}   (re-runs only if a source file changed)
  slice      {file, line, var}           -> forward slice (variables and lines by file) or null
  taint      {file, line, var}           -> {path: steps from a source to this variable, findings: through it}
  profile    {file, line, var}           -> the variable's srcSlice profile in its own function
  shutdown   {}                          -> null, then the process exits
File paths are relative to root, as srcSlice reports them.
"""
from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path

from .analysis import Analysis, analyze
from .profiles import fingerprint, tool_versions
from .cli import CACHE


class Server:
    def __init__(self) -> None:
        self.root: Path | None = None
        self.max_hops = 6
        self.an: Analysis | None = None
        self.findings: list = []

    def _refresh(self) -> float:
        t = time.perf_counter()
        if self.an is not None and fingerprint(self.root) == self.an.archive.digest:
            return time.perf_counter() - t          # nothing changed: keep the analysis
        an = analyze(self.root, CACHE, self.max_hops)
        if self.an is None or an.archive.digest != self.an.archive.digest:
            self.an, self.findings = an, an.findings()
        return time.perf_counter() - t

    def initialize(self, root: str, maxHops: int = 6) -> dict:
        self.root, self.max_hops, self.an = Path(root), maxHops, None
        sec = self._refresh()
        return {"versions": tool_versions(), "files": len({p.file for p in self.an.archive.profiles}),
                "profiles": len(self.an.prof), "findings": len(self.findings), "seconds": round(sec, 3),
                "skipped": self.an.archive.skipped}

    def analyze(self) -> dict:
        sec = self._refresh()
        return {"findings": [f.as_dict() for f in self.findings], "seconds": round(sec, 3),
                "skipped": self.an.archive.skipped}

    def slice(self, file: str, line: int, var: str):
        k = self.an.find_var(file, line, var)
        return self.an.forward_slice(k) if k else None

    def profile(self, file: str, line: int, var: str):
        """srcSlice's profile of the variable, limited to its own function, plus the calls it is passed to."""
        k = self.an.find_var(file, line, var)
        if k is None:
            return None
        p = self.an.prof[k]
        own = set(self.an.own_lines(k))
        calls = sorted({(c.name, j + 1) for c in self.an.calls_in.get((k[0], k[1]), [])
                        for j, a in enumerate(c.args) if var in a})
        return {"file": k[0], "function": k[1], "var": var, "defs": [d for d in p.defs if d in own],
                "uses": [u for u in p.uses if u in own],
                "dvars": [b[2] for b, how, _ in self.an.edges.get(k, []) if how in ("dvar", "sanitized", "field")],
                "aliases": sorted({b[2] for b, how, _ in self.an.edges.get(k, []) if how == "alias"}),
                "calls": [{"name": n, "arg": j} for n, j in calls],
                "pointsTo": sorted({f"{o[2]} ({o[0]}:{o[1]})" if o[3] != "function" else f"{o[2]}()"
                                    for o in self.an.pts.get(k, set())})}

    def taint(self, file: str, line: int, var: str):
        k = self.an.find_var(file, line, var)
        if k is None:
            return None
        parent = self.an._taint()
        path = [s.as_dict() for s in self.an._path(parent, k)] if k in parent else []
        through = [f.as_dict() for f in self.findings
                   if any(s.var == var and s.function == k[1] and s.file == file for s in f.path)]
        return {"path": path, "findings": through}


def main() -> None:
    srv = Server()
    out = sys.stdout
    sys.stdout = sys.stderr          # nothing but responses on the protocol stream
    for raw in sys.stdin:
        if not raw.strip():
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError as e:
            out.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": str(e)}}) + "\n")
            out.flush()
            continue
        rid, method, params = req.get("id"), req.get("method", ""), req.get("params") or {}
        try:
            if method == "shutdown":
                out.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": None}) + "\n")
                out.flush()
                return
            if method not in ("initialize", "analyze", "slice", "taint", "profile"):
                raise LookupError(f"unknown method {method}")
            if method != "initialize" and srv.an is None:
                raise RuntimeError("call initialize first")
            res = getattr(srv, method)(**params)
            out.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}) + "\n")
        except Exception as e:   # report, keep serving
            traceback.print_exc()
            out.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                  "error": {"code": -32000, "message": f"{type(e).__name__}: {e}"}}) + "\n")
        out.flush()


if __name__ == "__main__":
    main()

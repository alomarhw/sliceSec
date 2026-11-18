"""Command line: scan a folder, or print the forward slice of one variable.

    slicesec scan PATH [--format text|json|sarif] [--max-hops N] [--fail-on-findings]
    slicesec slice PATH FILE LINE VAR
    slicesec version
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .analysis import analyze
from .profiles import tool_versions

CACHE = Path.home() / ".cache" / "slicesec"


def sarif(findings, root: Path) -> dict:
    rules = sorted({(f.rule, f.cwe) for f in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "slicesec", "version": __version__,
                                "rules": [{"id": r, "properties": {"cwe": c}} for r, c in rules]}},
            "results": [{
                "ruleId": f.rule, "level": f.severity, "message": {"text": f"{f.cwe}: {f.message}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                    "region": {"startLine": f.line}}}],
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": s.file},
                                                       "region": {"startLine": s.line}},
                                  "message": {"text": f"{s.var}: {s.how}"}}} for s in f.path]}]}] if f.path else [],
            } for f in findings]}]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="slicesec", description="srcSlice-based slices and taint paths")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("path", type=Path)
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("--max-hops", type=int, default=6, help="longest taint path followed (0 = no limit)")
    s.add_argument("--fail-on-findings", action="store_true", help="exit 1 if anything is found (for CI)")
    sl = sub.add_parser("slice")
    sl.add_argument("path", type=Path)
    sl.add_argument("file")
    sl.add_argument("line", type=int)
    sl.add_argument("var")
    sub.add_parser("version")
    a = ap.parse_args(argv)

    if a.cmd == "version":
        print(f"slicesec {__version__}", *(f"{k} {v}" for k, v in tool_versions().items()), sep="\n")
        return 0
    t0 = time.perf_counter()
    an = analyze(a.path, CACHE, getattr(a, "max_hops", 6))
    if a.cmd == "slice":
        k = an.find_var(a.file, a.line, a.var)
        if k is None:
            print(f"no variable {a.var} at {a.file}:{a.line}", file=sys.stderr)
            return 2
        print(json.dumps(an.forward_slice(k), indent=1))
        return 0
    fs = an.findings()
    if a.format == "json":
        print(json.dumps([f.as_dict() for f in fs], indent=1))
    elif a.format == "sarif":
        print(json.dumps(sarif(fs, a.path), indent=1))
    else:
        for f in fs:
            print(f"{f.file}:{f.line}: {f.severity}: {f.cwe} {f.rule}: {f.message}")
            for st in f.path:
                print(f"    {st.file}:{st.line}  {st.var:<16} {st.how}")
        files = len({p.file for p in an.archive.profiles})
        print(f"\n{len(fs)} findings in {files} files, {len(an.prof)} slice profiles, "
              f"{time.perf_counter() - t0:.1f} s", file=sys.stderr)
        if an.archive.skipped:
            print(f"skipped (srcML could not convert): {', '.join(an.archive.skipped)}", file=sys.stderr)
    return 1 if a.fail_on_findings and fs else 0


if __name__ == "__main__":
    sys.exit(main())

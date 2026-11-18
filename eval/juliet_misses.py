"""Categorize the Juliet test cases sliceSec misses (same scoring as juliet_eval.py, sliceSec only, cached archives).
Run:  python3 eval/juliet_misses.py > eval/juliet_misses.txt"""
import re
import sys
from collections import Counter
from pathlib import Path

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / "slicesec"))
sys.path.insert(0, str(W / "eval"))
from juliet_eval import CASE, JULIET, TARGETS, CACHE, units  # noqa: E402
from slicesec.analysis import analyze  # noqa: E402


def category(case: str) -> str:
    v = case.split("__", 1)[1]
    if "w32" in v:
        return "Windows-only API (w32)"
    if v.startswith("wchar_t"):
        return "wide-character variant (wchar_t)"
    if "new_delete" in v or "delete" in v:
        return "C++ new/delete"
    return "other"


for name, cwe in TARGETS.items():
    cases, hit = set(), set()
    for d in units(JULIET / name):
        files = [f for f in d.iterdir() if CASE.match(f.name)]
        if not files:
            continue
        cases |= {CASE.match(f.name)[1] for f in files}
        an = analyze(d, CACHE)
        for f in an.findings():
            m = CASE.match(Path(f.file).name)
            fn = an.index.function_at(f.file, f.line)
            if m and int(f.cwe.split("-")[1]) == cwe and fn and "bad" in fn.name.lower():
                hit.add(m[1])
    miss = cases - hit
    byc = Counter(category(c) for c in miss)
    allc = Counter(category(c) for c in cases)
    print(f"{name}: {len(cases)} cases, {len(hit)} detected, {len(miss)} missed")
    for k in sorted(allc):
        print(f"   {k:<34} {allc[k]:>5} cases, {byc.get(k, 0):>5} missed")
    other = Counter(re.sub(r"_\d+$", "", c.split("__", 1)[1]) for c in miss if category(c) == "other")
    print("   other, most common:", other.most_common(8))

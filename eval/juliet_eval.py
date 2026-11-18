"""V1: detection on Juliet C/C++ 1.3 for CWE-78, 134, 415 and 416. sliceSec against flawfinder and cppcheck.

Scoring, per Juliet test case (files CWE..._NN[a-e].c/.cpp share one test case):
  detected      the tool warns with the test case's CWE inside a function whose name contains "bad"
  false alarm   the tool warns with that CWE inside a function whose name contains "good"
Each warning is placed in a function by line, using the function spans from the srcML archive sliceSec builds,
so all three tools are placed the same way. Recall = detected / cases; precision = detected / (detected +
false alarms), both counted in test cases.

Run:  JULIET_DIR=.../C/testcases python3 eval/juliet_eval.py > eval/juliet_eval.txt   (also writes eval/juliet_eval.json)
Needs srcml, srcslice, flawfinder and cppcheck on PATH (or FLAWFINDER=path).
"""
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / "slicesec"))
from slicesec.analysis import analyze  # noqa: E402

JULIET = Path(os.environ.get("JULIET_DIR", W / "data" / "juliet" / "C" / "testcases"))  # Juliet 1.3 C/testcases
CACHE = W / ".cache"
FLAWFINDER = os.environ.get("FLAWFINDER", "flawfinder")
TARGETS = {"CWE78_OS_Command_Injection": 78, "CWE134_Uncontrolled_Format_String": 134,
           "CWE415_Double_Free": 415, "CWE416_Use_After_Free": 416}
CASE = re.compile(r"^(CWE\d+_.+_\d+)[a-z]?\.(c|cpp)$")


def units(cwe_dir: Path):
    subs = sorted(d for d in cwe_dir.iterdir() if d.is_dir())
    return subs or [cwe_dir]


def run_flawfinder(d: Path):
    r = subprocess.run([str(FLAWFINDER), "--csv", "--quiet", "--dataonly", "--minlevel=0", str(d)],
                       capture_output=True, text=True)
    out = []
    for row in csv.DictReader(io.StringIO(r.stdout)):
        nums = {int(x) for x in re.findall(r"CWE-(\d+)", row.get("CWEs", ""))}
        out.append((os.path.relpath(row["File"], d), int(row["Line"]), nums))
    return out


def run_cppcheck(d: Path):
    if not shutil.which("cppcheck"):
        return []
    r = subprocess.run(["cppcheck", "--enable=warning", "--xml", "-q", "-j", "8", "--suppress=missingInclude",
                        "-I", str(JULIET.parent / "testcasesupport"), str(d)], capture_output=True, text=True)
    out = []
    try:
        root = ET.fromstring(r.stderr)
    except ET.ParseError:
        return out
    for e in root.iter("error"):
        cwe = int(e.get("cwe", "0") or 0)
        for loc in e.findall("location")[:1]:
            out.append((os.path.relpath(loc.get("file"), d), int(loc.get("line")), {cwe}))
    return out


def main():
    totals = {}
    detail = {}
    only = os.environ.get("ONLY")
    for name, cwe in TARGETS.items():
        if only and only not in name:
            continue
        cases = set()
        hit = {t: set() for t in ("sliceSec", "flawfinder", "cppcheck")}
        fa = {t: set() for t in hit}
        secs = defaultdict(float)
        for d in units(JULIET / name):
            files = [f for f in d.iterdir() if CASE.match(f.name)]
            if not files:
                continue
            cases |= {CASE.match(f.name)[1] for f in files}
            t = time.perf_counter()
            an = analyze(d, CACHE)
            fs = an.findings()
            secs["sliceSec"] += time.perf_counter() - t
            warnings = {"sliceSec": [(f.file, f.line, {int(f.cwe.split("-")[1])}) for f in fs]}
            t = time.perf_counter(); warnings["flawfinder"] = run_flawfinder(d); secs["flawfinder"] += time.perf_counter() - t
            t = time.perf_counter(); warnings["cppcheck"] = run_cppcheck(d); secs["cppcheck"] += time.perf_counter() - t
            for tool, ws in warnings.items():
                for file, line, cwes in ws:
                    m = CASE.match(Path(file).name)
                    if not m or cwe not in cwes:
                        continue
                    fn = an.index.function_at(file, line)
                    fname = (fn.name if fn else "").lower()
                    if "bad" in fname:
                        hit[tool].add(m[1])
                    elif "good" in fname:
                        fa[tool].add(m[1])
            print(f"  {name}/{d.name}: {len(files)} files, sliceSec {len(fs)} findings, skipped {an.archive.skipped}",
                  file=sys.stderr, flush=True)
        totals[name] = {"cases": len(cases), "seconds": {k: round(v, 1) for k, v in secs.items()}}
        for tool in hit:
            tp, fp = len(hit[tool]), len(fa[tool])
            totals[name][tool] = {"detected": tp, "false_alarm": fp, "recall": round(tp / len(cases), 3),
                                  "precision": round(tp / (tp + fp), 3) if tp + fp else None}
        detail[name] = {tool: {"missed": sorted(cases - hit[tool])[:2000], "false_alarm": sorted(fa[tool])}
                        for tool in hit}
    (W / "eval" / "juliet_eval.json").write_text(json.dumps({"totals": totals, "detail": detail}, indent=1))
    print(f"# Juliet C/C++ 1.3, {time.strftime('%Y-%m-%d')}; srcml/srcslice from PATH; flawfinder "
          f"{subprocess.run([str(FLAWFINDER), '--version'], capture_output=True, text=True).stdout.strip()}; "
          f"{subprocess.run(['cppcheck', '--version'], capture_output=True, text=True).stdout.strip() if shutil.which('cppcheck') else 'cppcheck MISSING'}")
    print(f"{'CWE':<36}{'cases':>6}  {'tool':<11}{'detected':>9}{'false alarm':>12}{'recall':>8}{'precision':>10}{'sec':>7}")
    for name, t in totals.items():
        for tool in ("sliceSec", "flawfinder", "cppcheck"):
            r = t[tool]
            print(f"{name:<36}{t['cases']:>6}  {tool:<11}{r['detected']:>9}{r['false_alarm']:>12}{r['recall']:>8}"
                  f"{str(r['precision']):>10}{t['seconds'].get(tool, 0):>7}")


if __name__ == "__main__":
    main()

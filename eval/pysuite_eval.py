"""Python sanity check: sliceSec and Bandit on runs/pysuite (functions named bad_* / good_*, written for this paper).

A tool detects a bad function if it warns with the file's CWE inside it, and raises a false alarm on a good
function the same way. Bandit's rules are matched to the CWE by test id: CWE-78 B602, B605, B609; CWE-95 B307,
B102; CWE-89 B608; CWE-22 none (Bandit has no path rule). Run:  python3 eval/pysuite_eval.py > eval/pysuite_eval.txt
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / "slicesec"))
from slicesec.analysis import analyze  # noqa: E402

SUITE = W / "eval" / "pysuite"
BANDIT = os.environ.get("BANDIT", "bandit")
BANDIT_IDS = {78: {"B602", "B605", "B609"}, 95: {"B307", "B102"}, 89: {"B608"}, 22: set()}

an = analyze(SUITE, W / ".cache")
funcs = {(f.file, f.name) for f in an.index.functions if f.name.startswith(("bad", "good")) and "_sink_" not in f.name}


def case(name: str) -> str:
    """A *_sink_* helper belongs to its file's bad_interprocedural / good_interprocedural case."""
    return name.split("_sink_")[0] + "_interprocedural" if "_sink_" in name else name
cwe_of = {f: int(re.match(r"cwe(\d+)", f).group(1)) for f in {f for f, _ in funcs}}

warn = {"sliceSec": [(f.file, f.line, int(f.cwe.split("-")[1])) for f in an.findings()], "Bandit": []}
r = subprocess.run([str(BANDIT), "-r", "-f", "json", "-q", str(SUITE)], capture_output=True, text=True)
for i in json.loads(r.stdout)["results"]:
    file = Path(i["filename"]).name
    for cwe, ids in BANDIT_IDS.items():
        if i["test_id"] in ids:
            warn["Bandit"].append((file, i["line_number"], cwe))

print(f"# Python sanity check, {len(funcs)} functions; {subprocess.run([str(BANDIT), '--version'], capture_output=True, text=True).stdout.splitlines()[0]}")
print(f"{'file':<10}{'bad':>4}{'good':>5}  {'tool':<9}{'detected':>9}{'false alarm':>12}")
for file in sorted(cwe_of):
    bad = {n for f, n in funcs if f == file and n.startswith("bad")}
    good = {n for f, n in funcs if f == file and n.startswith("good")}
    for tool, ws in warn.items():
        hit, fa = set(), set()
        for f, line, cwe in ws:
            if f != file or cwe != cwe_of[file]:
                continue
            fn = an.index.function_at(f, line)
            name = case(fn.name) if fn else ""
            if name in bad:
                hit.add(name)
            elif name in good:
                fa.add(name)
        print(f"{file:<10}{len(bad):>4}{len(good):>5}  {tool:<9}{len(hit):>9}{len(fa):>12}   fa={sorted(fa)}")

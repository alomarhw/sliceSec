"""V2: speed on real projects, and the latency of slice and taint queries on 200 variables drawn at random (seed 1).
The first analysis is timed by stage; then a
save that changes nothing (the server only compares the fingerprint), then a save that edits one file (srcML and
srcSlice run again on the archive). Run alone (no other heavy jobs):
    PROJECTS=... python3 eval/speed.py > eval/speed.txt
"""
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / "slicesec"))
from slicesec import profiles  # noqa: E402
from slicesec.analysis import Analysis, analyze  # noqa: E402
from slicesec.srcml_index import build  # noqa: E402

# the projects: PROJECTS="dir1:dir2:..." (the paper used clones of tcpdump, libxml2, libtiff, openjpeg and curl, and
# the pip package's source; their commits are in speed_projects.txt)
PROJECTS = [Path(p) for p in os.environ["PROJECTS"].split(":")]


def ms(xs):
    return f"median {statistics.median(xs) * 1000:.1f} ms, p95 {sorted(xs)[int(len(xs) * .95)] * 1000:.1f} ms"


cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
mem = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout) // 2 ** 30
print(f"# {cpu}, {mem} GB, macOS {platform.mac_ver()[0]}, Python {platform.python_version()}; {profiles.tool_versions()}")
print("project files LOC | srcML s | srcSlice s | index+graph s | rules s | first analysis s | unchanged save s | "
      "save after an edit s | profiles edges findings | slice query | taint query")
for root in PROJECTS:
    files = profiles.source_files(root)
    loc = sum(len(f.read_bytes().splitlines()) for f in files)
    with tempfile.TemporaryDirectory() as cache:
        cache = Path(cache)
        # cold, staged: time srcML alone, then srcSlice on its output, by running profiles.run and splitting
        t0 = time.perf_counter()
        orig = subprocess.run
        stamps = {}

        def timed(cmd, *a, **k):
            t = time.perf_counter()
            r = orig(cmd, *a, **k)
            stamps[cmd[0]] = stamps.get(cmd[0], 0) + time.perf_counter() - t
            return r
        profiles.subprocess.run = timed
        arch = profiles.run(root, cache)
        profiles.subprocess.run = orig
        t1 = time.perf_counter()
        an = Analysis(arch, build(str(arch.xml)))
        t2 = time.perf_counter()
        fs = an.findings()
        t3 = time.perf_counter()
        t = time.perf_counter()
        same = profiles.fingerprint(root) == arch.digest       # a save that changes nothing: the server keeps
        unchanged = time.perf_counter() - t                      # its analysis after this check
        # a save that edits one file: its modification time changes, so srcML and srcSlice run again
        f0 = files[0]
        st = f0.stat()
        os.utime(f0, ns=(st.st_atime_ns, st.st_mtime_ns + 1000))
        try:
            t = time.perf_counter()
            an2 = analyze(root, cache)
            an2.findings()
            resave = time.perf_counter() - t
        finally:
            os.utime(f0, ns=(st.st_atime_ns, st.st_mtime_ns))
    keys = list(an.prof)
    random.Random(1).shuffle(keys)
    sl, ta = [], []
    for k in keys[:200]:
        t = time.perf_counter(); an.forward_slice(k); sl.append(time.perf_counter() - t)
        t = time.perf_counter(); p = an._taint(); an._path(p, k) if k in p else None; ta.append(time.perf_counter() - t)
    name = root.name if root.name != "pip" else "pip (Python)"
    print(f"{name} {len(files)} {loc} | {stamps.get('srcml', 0):.1f} | {stamps.get('srcslice', 0):.1f} | {t2 - t1:.1f} | "
          f"{t3 - t2:.2f} | {t3 - t0:.1f} | {unchanged:.3f} (same={same}) | {resave:.1f} | {len(an.prof)} {sum(map(len, an.edges.values()))} {len(fs)} | "
          f"{ms(sl)} | {ms(ta)} | skipped {arch.skipped}", flush=True)

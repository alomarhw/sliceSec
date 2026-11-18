"""Run srcML and srcSlice on a folder and read srcSlice's slice profiles.

srcSlice prints one profile per line on stdout:
    file,function,var,def{l,..},use{l,..},dvars{v,..},pointers{v,..},cfuncs{f{k},..}
(its "Time is" line goes to stderr, so no stdout line is skipped). Interprocedural use is already folded in by
srcSlice: a variable passed to a function defined in the archive gets that function's use lines and calls.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".py"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "build", "dist"}


@dataclass
class Profile:
    file: str
    function: str
    var: str
    defs: list[int]
    uses: list[int]
    dvars: list[str]
    pointers: list[str]
    cfuncs: list[tuple[str, int]]   # (callee short name, 1-based argument position)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.file, self.function, self.var)

    @property
    def lines(self) -> list[int]:
        return sorted(set(self.defs) | set(self.uses))


_REC = re.compile(r"^(?P<file>.*?),(?P<func>[^,]*),(?P<var>[^,]*),def\{(?P<d>[^}]*)\},use\{(?P<u>[^}]*)\},"
                  r"dvars\{(?P<dv>[^}]*)\},pointers\{(?P<p>[^}]*)\},cfuncs\{(?P<cf>.*)\}\s*$")
_CF = re.compile(r"([^{},]+)\{(\d+)\}")


def _ints(s: str) -> list[int]:
    return [int(x) for x in s.split(",") if x.strip().isdigit()]


def _strs(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def parse(text: str) -> list[Profile]:
    out = []
    for line in text.splitlines():
        m = _REC.match(line)
        if not m:
            continue
        out.append(Profile(m["file"], m["func"], m["var"], _ints(m["d"]), _ints(m["u"]), _strs(m["dv"]),
                           _strs(m["p"]), [(n.strip(), int(k)) for n, k in _CF.findall(m["cf"])]))
    return out


def tool_versions() -> dict[str, str]:
    v = {}
    for t in ("srcml", "srcslice"):
        p = shutil.which(t)
        if p is None:
            raise RuntimeError(f"{t} not found on PATH; install srcML 1.1 and srcSlice (see README)")
        r = subprocess.run([t, "--version"], capture_output=True, text=True)
        v[t] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else "unknown"
    return v


def source_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
        out += [Path(dp) / f for f in fns if Path(f).suffix in EXTS]
    return sorted(out)


def fingerprint(root: Path, files: list[Path] | None = None) -> str:
    """Names, sizes and modification times of the source files: unchanged means the analysis can be reused."""
    h = hashlib.sha256()
    for f in files if files is not None else source_files(root.resolve()):
        st = f.stat()
        h.update(f"{f}:{st.st_mtime_ns}:{st.st_size}\n".encode())
    return h.hexdigest()[:16]


@dataclass
class Archive:
    root: Path
    xml: Path
    profiles: list[Profile] = field(default_factory=list)
    digest: str = ""
    skipped: list[str] = field(default_factory=list)   # files srcML could not turn into well-formed XML


def run(root: Path, cache_dir: Path) -> Archive:
    """srcML archive of every C/C++/Python file under root, then srcSlice. Cached by file names and mtimes."""
    root = root.resolve()
    files = source_files(root)
    if not files:
        raise RuntimeError(f"no C, C++ or Python files under {root}")
    digest = fingerprint(root, files)
    cache_dir = cache_dir.resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    xml, out = cache_dir / f"{digest}.xml", cache_dir / f"{digest}.slices"
    skipped_file = cache_dir / f"{digest}.skipped"
    if not out.exists():
        rel = [str(f.relative_to(root)) if root.is_dir() else f.name for f in files]
        cwd = root if root.is_dir() else root.parent
        lst = cache_dir / f"{digest}.files"
        lst.write_text("\n".join(rel) + "\n")
        subprocess.run(["srcml", "--position", "--files-from", str(lst), "-o", str(xml)], cwd=cwd, check=True,
                       capture_output=True)
        skipped = []
        if not _well_formed(xml):
            # srcML 1.1 can emit malformed XML for some inputs (an unclosed <attribute> for a function declared
            # with __attribute__((no_sanitize(..)))). Leave those files out and say so.
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
                ok = list(ex.map(lambda f: _converts(cwd / f), rel))
            skipped = [f for f, good in zip(rel, ok) if not good]
            lst.write_text("\n".join(f for f in rel if f not in skipped) + "\n")
            subprocess.run(["srcml", "--position", "--files-from", str(lst), "-o", str(xml)], cwd=cwd,
                           check=True, capture_output=True)
        r = subprocess.run(["srcslice", str(xml)], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"srcslice failed: {r.stderr[-400:]}")
        out.write_text(r.stdout)
        skipped_file.write_text("\n".join(skipped))
    skipped = [x for x in skipped_file.read_text().splitlines() if x] if skipped_file.exists() else []
    return Archive(root, xml, parse(out.read_text()), digest, skipped)


def _well_formed(xml: Path) -> bool:
    import xml.etree.ElementTree as ET
    try:
        for _ in ET.iterparse(xml):
            pass
        return True
    except ET.ParseError:
        return False


def _converts(src: Path) -> bool:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        o = Path(d) / "one.xml"
        r = subprocess.run(["srcml", "--position", str(src), "-o", str(o)], capture_output=True)
        return r.returncode == 0 and _well_formed(o)

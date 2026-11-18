"""Forward slices, taint paths and rule findings on top of srcSlice's profiles.

A node is a variable in a function: (file, function, var), one srcSlice profile. Edges:
  dvar      v -> d       d's value is computed from v (srcSlice dvars, confirmed on d's def line)
  alias     p <-> q      q points to p (srcSlice pointers, confirmed on a def line)
  call      arg -> param v is passed to a function defined in the archive (srcML call sites)
  out       param -> arg the callee writes through a pointer parameter (srcSlice lists the argument among the
                         parameter's pointers)
  return    ret -> x     x is assigned the result of such a function, which returns ret
  copy      src -> dst   a library copy (strcpy, memcpy, sprintf, ..) from the srcML call sites
srcSlice folds every callee's facts into its callers' profiles; edges use only facts the source line confirms, and
calls come from the call sites, so each edge is one real step. The forward slice of a variable is the def and use
lines of every node reachable from it. A taint path is a shortest path from a source to a variable used at a
sink's dangerous argument. A dvar edge whose target is assigned from a sanitizer (n = atoi(buf)), or whose target
is only written through a field (ctx->f = v), is kept for slicing and skipped by taint.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from . import rules as R
from .profiles import Archive, Profile, run as run_srcslice
from .srcml_index import Call, Index, build as build_index

Key = tuple[str, str, str]   # file, function, var


@dataclass
class Step:
    file: str
    line: int
    var: str
    function: str
    how: str          # "source", "dvar", "alias", "call", "copy", "return", "sink"

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Finding:
    rule: str
    cwe: str
    severity: str
    message: str
    file: str
    line: int
    function: str
    sink: str
    path: list[Step] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "path"}
        d["path"] = [s.as_dict() for s in self.path]
        return d


def _is_py(file: str) -> bool:
    return file.endswith(".py")


class Analysis:
    def __init__(self, archive: Archive, index: Index, max_hops: int = 6):
        self.archive, self.index, self.max_hops = archive, index, max_hops
        self.prof: dict[Key, Profile] = {p.key: p for p in archive.profiles}
        self.by_var: dict[tuple[str, str], list[Key]] = {}
        for k in self.prof:
            self.by_var.setdefault((k[0], k[2]), []).append(k)
        self.calls_at: dict[tuple[str, int], list[Call]] = {}
        self.calls_in: dict[tuple[str, str], list[Call]] = {}
        for c in index.calls:
            self.calls_at.setdefault((c.file, c.line), []).append(c)
            self.calls_in.setdefault((c.file, c.function), []).append(c)
        self.fn_named: dict[str, list] = {}
        for fn in index.functions:
            self.fn_named.setdefault(fn.name, []).append(fn)
        self.edges: dict[Key, list[tuple[Key, str, int]]] = {}   # node -> [(node, how, line)]
        self._build_edges()

    # ---- source text -------------------------------------------------------------------------------------
    def src_line(self, file: str, line: int) -> str:
        if not hasattr(self, "_src"):
            self._src: dict[str, list[str]] = {}
        if file not in self._src:
            base = self.archive.root if self.archive.root.is_dir() else self.archive.root.parent
            try:
                self._src[file] = (base / file).read_text(errors="replace").splitlines()
            except OSError:
                self._src[file] = []
        ls = self._src[file]
        return ls[line - 1] if 0 < line <= len(ls) else ""

    def _field_write(self, t: Key) -> bool:
        """Every def of t writes a field (t->f = .., t.f = ..), never t itself. Such a dvar edge is kept for
        slicing but does not carry taint: srcSlice's profiles are field insensitive, so following it would taint
        the whole struct (a context object passed to most functions)."""
        p = self.prof.get(t)
        if not p or not p.defs:
            return False
        v = re.escape(t[2])
        fld = re.compile(rf"\b{v}\s*(->|\.|\[)[^=;]*[^=!<>]=[^=]")
        whole = re.compile(rf"(^|[^.>\w]){v}\s*[-+*/|&^]?=[^=]")
        return all(fld.search(self.src_line(t[0], d)) and not whole.search(self.src_line(t[0], d)) for d in p.defs)

    def _plain_alias(self, q: Key, p: Key, before: int) -> bool:
        """q = p (optionally cast) or p = q on a def line before `before`: a real pointer copy."""
        for a, b in ((q, p), (p, q)):
            pat = re.compile(rf"(^|[^.>\w]){re.escape(a[2])}\s*=\s*(\([^()]*\)\s*)?{re.escape(b[2])}\s*[;,)]")
            if any(d < before and pat.search(self.src_line(a[0], d)) for d in self.prof[a].defs):
                return True
        return False

    # ---- graph -------------------------------------------------------------------------------------------
    def node(self, file: str, function: str, var: str) -> Key | None:
        k = (file, function, var)
        return k if k in self.prof else None

    def _on_def_line(self, a: Key, b: str) -> bool:
        """b occurs as a word on one of a's def lines inside a's own function. srcSlice folds the facts of every
        callee into a caller's profile (a context pointer passed everywhere collects hundreds of dvars), so a
        dvar or pointer is used as an edge only when the source line confirms it."""
        fn = self.index.function_at(a[0], (self.prof[a].defs or [0])[0]) if a[1] else None
        w = re.compile(rf"(^|[^\w]){re.escape(b)}($|[^\w])")
        for d in self.prof[a].defs:
            if fn is not None and not (fn.start <= d <= fn.end):
                continue
            if w.search(self.src_line(a[0], d)):
                return True
        return False

    def _local_call(self, c: Call) -> bool:
        """A call can reach a function defined in the archive only if it is bare (run(x)) or qualified by a local
        variable, self, this or cls (r.find(u)); subprocess.run or std::system name a library function."""
        parts = c.name.replace("::", ".").split(".")
        return len(parts) == 1 or parts[0] in ("self", "this", "cls") or (c.file, c.function, parts[0]) in self.prof

    def _add(self, a: Key, b: Key | None, how: str, line: int) -> None:
        if b is not None and b != a:
            self.edges.setdefault(a, []).append((b, how, line))

    def _sanitized(self, src: Key, dst: Key) -> bool:
        """dst = sanitizer(src) on one of dst's def lines."""
        san = R.PY_SANITIZERS if _is_py(src[0]) else R.C_SANITIZERS
        dp = self.prof.get(dst)
        for line in (dp.defs if dp else []):
            for c in self.calls_at.get((dst[0], line), []):
                if c.target == dst[2] and R.name_matches(c.name, san) and any(src[2] in a for a in c.args):
                    return True
        return False

    def _build_edges(self) -> None:
        for k, p in self.prof.items():
            for d in p.dvars:
                t = (k[0], k[1], d)
                if t in self.prof and self._on_def_line(t, k[2]):
                    how = "sanitized" if self._sanitized(k, t) else "field" if self._field_write(t) else "dvar"
                    self._add(k, t, how, (self.prof[t].defs or [0])[0])
            for q in p.pointers:
                t = (k[0], k[1], q)
                if t in self.prof and (self._on_def_line(k, q) or self._on_def_line(t, k[2])):
                    self._add(t, k, "alias", (p.defs or [0])[0])
                    self._add(k, t, "alias", (p.defs or [0])[0])
        for c in self.index.calls:      # argument -> parameter, and callee return value -> assigned variable
            if not self._local_call(c):
                continue
            for fn in self.fn_named.get(c.short, []):
                off = 1 if (fn.params[:1] in (["self"], ["cls"]) and "." in c.name) else 0
                for j, names in enumerate(c.args):
                    if j + off < len(fn.params):
                        for v in names:
                            a, t = self.node(c.file, c.function, v), self.node(fn.file, fn.name, fn.params[j + off])
                            self._add(a, t, "call", c.line)
                            # an output parameter: srcSlice lists the caller's argument among the parameter's
                            # pointers, so what the callee writes through it reaches the caller's variable
                            if a and t and v in self.prof[t].pointers:
                                self._add(t, a, "out", c.line)
                if c.target:
                    for v in self.index.returns.get((fn.file, fn.name), ()):
                        self._add(self.node(fn.file, fn.name, v), self.node(c.file, c.function, c.target),
                                  "return", c.line)
        for c in self.index.calls:
            spec = None if _is_py(c.file) else R.C_PROPAGATORS.get(c.short)
            if spec is None:
                continue
            src_pos, dst_pos = spec
            if dst_pos == 0:
                dst_names = [c.target] if c.target else []
            else:
                dst_names = [next((n for n in c.args[d - 1] if self.node(c.file, c.function, n)), None)
                             for d in R.positions(dst_pos if isinstance(dst_pos, str) else (dst_pos,), len(c.args))]
                dst_names = [n for n in dst_names if n]
            for sp in R.positions(src_pos if isinstance(src_pos, str) else (src_pos,), len(c.args)):
                for s in c.args[sp - 1]:
                    for d in dst_names:
                        self._add(self.node(c.file, c.function, s), self.node(c.file, c.function, d),
                                  "copy" if dst_pos else "return", c.line)

    # ---- slices ------------------------------------------------------------------------------------------
    def own_lines(self, k: Key) -> list[int]:
        """k's def and use lines inside its own function (srcSlice also lists the lines of callees it reaches,
        which the slice covers through the callee's own parameter node)."""
        p = self.prof[k]
        fn = next((f for f in self.fn_named.get(k[1], []) if f.file == k[0]
                   and any(f.start <= d <= f.end for d in p.defs)), None) if k[1] else None
        # srcSlice's folded use lines carry no file name: keep a line only if the variable is written on it
        w = re.compile(rf"(^|[^\w]){re.escape(k[2])}($|[^\w])")
        return [l for l in p.lines if (fn is None or fn.start <= l <= fn.end) and w.search(self.src_line(k[0], l))]

    def find_var(self, file: str, line: int, var: str) -> Key | None:
        fn = self.index.function_at(file, line)
        return self.node(file, fn.name if fn else "", var)

    def forward_slice(self, start: Key) -> dict:
        seen, todo = {start}, deque([start])
        while todo:
            for b, _, _ in self.edges.get(todo.popleft(), []):
                if b not in seen:
                    seen.add(b)
                    todo.append(b)
        lines: dict[str, set[int]] = {}
        for k in seen:
            lines.setdefault(k[0], set()).update(self.own_lines(k))
        return {"criterion": {"file": start[0], "function": start[1], "var": start[2]},
                "variables": sorted([{"file": f, "function": fn, "var": v} for f, fn, v in seen],
                                    key=lambda x: (x["file"], x["function"], x["var"])),
                "lines": {f: sorted(ls) for f, ls in sorted(lines.items())}}

    # ---- taint -------------------------------------------------------------------------------------------
    def sources(self) -> list[tuple[Key, Step]]:
        out = []
        for c in self.index.calls:
            py = _is_py(c.file)
            if py and R.name_matches(c.name, R.PY_SOURCE_RETURNS) or not py and c.short in R.C_SOURCE_RETURNS:
                if c.target and not c.compared:
                    k = self.node(c.file, c.function, c.target)
                    if k:
                        out.append((k, Step(c.file, c.line, c.target, c.function, f"source: {c.name}()")))
            if not py and c.short in R.C_SOURCE_ARGS:
                spec = R.C_SOURCE_ARGS[c.short]
                for pos in R.positions(spec if isinstance(spec, str) else tuple(spec), len(c.args)):
                    # the buffer written: the first name that is a variable here ((char *)(data + n) -> data)
                    k = next((self.node(c.file, c.function, v) for v in c.args[pos - 1]
                              if self.node(c.file, c.function, v)), None)
                    if k:
                        out.append((k, Step(c.file, c.line, k[2], c.function, f"source: {c.name}()")))
        for c in self.index.calls:        # f(input()): the source's value goes straight into f's parameter
            if not self._local_call(c) or c.short not in self.fn_named:
                continue
            for j in range(1, len(c.args) + 1):
                st = self._source_in_arg(c, j)
                if st is None:
                    continue
                for fn in self.fn_named[c.short]:
                    off = 1 if (fn.params[:1] in (["self"], ["cls"]) and "." in c.name) else 0
                    if j - 1 + off < len(fn.params):
                        k = self.node(fn.file, fn.name, fn.params[j - 1 + off])
                        if k:
                            out.append((k, st))
        for f, fn, line, stream, v in self.index.extractions:
            k = self.node(f, fn, v)
            if k:
                out.append((k, Step(f, line, v, fn, f"source: {stream} >>")))
        for fn in self.index.functions:   # command-line arguments
            if fn.name == "main" and not _is_py(fn.file) and len(fn.params) >= 2:
                k = self.node(fn.file, "main", fn.params[1])
                if k:
                    out.append((k, Step(fn.file, fn.start, fn.params[1], "main", "source: argv")))
        return out

    def _is_source_call(self, x: Call) -> bool:
        if _is_py(x.file):
            return R.name_matches(x.name, R.PY_SOURCE_RETURNS)
        return x.short in R.C_SOURCE_RETURNS

    def _inner_calls(self, c: Call, pos: int) -> list[Call]:
        """Calls written inside c's argument pos (same line, their text appears in the argument)."""
        if pos > len(c.arg_texts):
            return []
        t = c.arg_texts[pos - 1]
        return [x for x in self.calls_at.get((c.file, c.line), []) if x is not c and (x.name + "(") in t]

    def _source_in_arg(self, c: Call, pos: int) -> Step | None:
        for x in self._inner_calls(c, pos):
            if self._is_source_call(x) and not x.compared:
                return Step(c.file, c.line, x.name + "()", c.function, f"source: {x.name}()")
        return None

    def _sanitized_in_arg(self, c: Call, pos: int, v: str) -> bool:
        san = R.PY_SANITIZERS if _is_py(c.file) else R.C_SANITIZERS
        return any(R.name_matches(x.name, san) and any(v in a for a in x.args) for x in self._inner_calls(c, pos))

    def _taint(self) -> dict[Key, tuple[Key | None, Step]]:
        """BFS from every source at once; parent pointers give one shortest path to each tainted node.
        Paths longer than max_hops edges are not followed: srcSlice's profiles are field insensitive, so on real
        code taint otherwise spreads through shared context structs (tcpdump's ndo) to most of the program.
        Computed once per analysis; queries reuse it."""
        if getattr(self, "_parent", None) is not None:
            return self._parent
        parent: dict[Key, tuple[Key | None, Step]] = {}
        depth: dict[Key, int] = {}
        todo = deque()
        for k, st in self.sources():
            if k not in parent:
                parent[k], depth[k] = (None, st), 0
                todo.append(k)
        while todo:
            a = todo.popleft()
            if self.max_hops and depth[a] >= self.max_hops:
                continue
            for b, how, line in self.edges.get(a, []):
                if how not in ("sanitized", "field") and b not in parent:
                    # a call step points at the call site, in the caller's file
                    st = Step(a[0], line, b[2], a[1], f"passed to {b[1]}()") if how == "call" else \
                        Step(b[0], line, b[2], b[1], f"written by {a[1]}()") if how == "out" else \
                        Step(b[0], line, b[2], b[1], how)
                    parent[b], depth[b] = (a, st), depth[a] + 1
                    todo.append(b)
        self._parent = parent
        return parent

    @staticmethod
    def _path(parent, k: Key) -> list[Step]:
        steps = []
        while k is not None:
            prev, st = parent[k]
            steps.append(st)
            k = prev
        return steps[::-1]

    def findings(self) -> list[Finding]:
        parent = self._taint()
        out: list[Finding] = []
        for c in self.index.calls:
            py = _is_py(c.file)
            if not py and c.short in R.C_ALWAYS and c.name in (c.short, "std::" + c.short):
                rule, cwe, msg = R.C_ALWAYS[c.short]
                out.append(Finding(rule, cwe, "warning", msg, c.file, c.line, c.function, c.name))
            for s in (R.PY_SINKS if py else R.C_SINKS):
                if not R.name_matches(c.name, s.names):
                    continue
                if s.kw and c.kwargs.get(s.kw[0]) != s.kw[1]:
                    continue
                for pos in R.positions(s.args, len(c.args)):
                    src = self._source_in_arg(c, pos)
                    if src is not None:
                        out.append(Finding(s.rule, s.cwe, s.severity, f"{s.message} ({src.how.removeprefix('source: ')})",
                                           c.file, c.line, c.function, c.name,
                                           [src, Step(c.file, c.line, src.var, c.function, f"sink: {c.name} argument {pos}")]))
                        break
                    for v in c.args[pos - 1]:
                        if self._sanitized_in_arg(c, pos, v):
                            continue
                        k = self.node(c.file, c.function, v)
                        if s.rule in ("tainted-length", "unbounded-copy") and v in c.guards:
                            continue    # inside if (v < bound) or similar
                        if k in parent:
                            path = self._path(parent, k) + [Step(c.file, c.line, v, c.function,
                                                                 f"sink: {c.name} argument {pos}")]
                            out.append(Finding(s.rule, s.cwe, s.severity, f"{s.message} ({v} via "
                                               f"{path[0].how.removeprefix('source: ')})", c.file, c.line,
                                               c.function, c.name, path))
                            break
        out += self._use_after_free()
        uniq = {}
        for f in out:
            uniq.setdefault((f.rule, f.file, f.line, f.sink), f)
        return sorted(uniq.values(), key=lambda f: (f.file, f.line, f.rule))

    def _first_use(self, node: Key, after: int, stop: int, depth: int) -> list[Step] | None:
        """The first use of node after line `after` (before `stop`, a redefinition or a jump), as path steps. A use
        that only passes the pointer to a function defined in the program is followed into that function: passing
        a freed pointer to a function that never reads it is not a use."""
        p = self.prof[node]
        fn = next((f for f in self.fn_named.get(node[1], []) if f.file == node[0]
                   and any(f.start <= d <= f.end for d in p.defs)), None)
        end = fn.end if fn else 10 ** 9
        redef = [d for d in p.defs if d > after]
        own = set(self.own_lines(node))
        for u in sorted(x for x in p.uses if x in own):
            if not (after < u <= end) or u >= stop or any(d <= u for d in redef):
                continue
            here = [c for c in self.calls_at.get((node[0], u), []) if any(node[2] in a for a in c.args)]
            local = [(b, ln) for b, how, ln in self.edges.get(node, []) if how == "call" and ln == u]
            if here and local and all(self._local_call(c) and c.short in self.fn_named for c in here):
                if depth >= 3:
                    return None
                for b, _ in local:
                    start = next((f.start for f in self.fn_named.get(b[1], []) if f.file == b[0]), 0)
                    sub = self._first_use(b, start, 10 ** 9, depth + 1)   # after the header that defines b
                    if sub:
                        return [Step(node[0], u, node[2], node[1], f"passed to {b[1]}()")] + sub
                continue            # passed on but never read there
            # x = p or x = *pp only copies the dangling pointer: follow x instead of reporting
            text = self.src_line(node[0], u)
            copy = re.compile(rf"(\w+)\s*=\s*(\([^()]*\)\s*)?\(?\s*\*?\s*{re.escape(node[2])}\s*\)?\s*;")
            m = copy.search(text)
            if m and (node[0], node[1], m.group(1)) in self.prof and m.group(1) != node[2]:
                if depth >= 3:
                    return None
                q = (node[0], node[1], m.group(1))
                sub = self._first_use(q, u, stop, depth + 1)
                if sub:
                    return [Step(node[0], u, q[2], node[1], "copied")] + sub
                continue
            return [Step(node[0], u, node[2], node[1], "used after free")]
        return None

    def _use_after_free(self) -> list[Finding]:
        out = []
        for c in self.index.calls:
            if _is_py(c.file) or c.short not in R.C_FREE or not c.args or not c.args[0]:
                continue
            if not re.fullmatch(r"(\([^()]*\))?[A-Za-z_]\w*", c.arg_texts[0]):   # free(s->buf) frees a member
                continue
            fn = self.index.function_at(c.file, c.line)
            if fn is None:
                continue
            root = self.node(c.file, fn.name, c.args[0][0])
            if root is None:
                continue
            aliases, todo = {root}, [root]
            while todo:
                a0 = todo.pop()
                for b, how, _ in self.edges.get(a0, []):
                    if how == "alias" and b not in aliases and b[1] == fn.name and self._plain_alias(b, a0, c.line):
                        aliases.add(b)
                        todo.append(b)
            for a in sorted(aliases):
                steps = self._first_use(a, c.line, c.jump_line or 10 ** 9, 0)
                if not steps:
                    continue
                last = steps[-1]
                at = self.calls_at.get((last.file, last.line), [])
                double = any(x.short in R.C_FREE and x.args and last.var in x.args[0] for x in at)
                rule, cwe = ("double-free", "CWE-415") if double else ("use-after-free", "CWE-416")
                path = [Step(c.file, c.line, root[2], fn.name, f"freed by {c.name}")]
                if a != root:
                    path.append(Step(c.file, (self.prof[a].defs or [c.line])[0], a[2], fn.name, "alias"))
                if double:
                    steps[-1] = Step(last.file, last.line, last.var, last.function, "freed again")
                what = "it is" if last.var == root[2] else f"{root[2]} is"
                msg = (f"{last.var} is freed again after {what} freed on line {c.line}" if double else
                       f"{last.var} is used after {what} freed on line {c.line}")
                out.append(Finding(rule, cwe, "error", msg, last.file, last.line, last.function, c.name,
                                   path + steps))
                break
        return out


def analyze(root: Path, cache_dir: Path, max_hops: int = 6) -> Analysis:
    archive = run_srcslice(root, cache_dir)
    return Analysis(archive, build_index(str(archive.xml)), max_hops)

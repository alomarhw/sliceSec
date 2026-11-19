"""Facts that srcSlice's profiles leave out, read from the same srcML archive.

srcSlice records, per variable, its def and use lines, dvars, pointers and the calls it is passed to (cfuncs, by
unqualified callee name and argument position). The analysis also needs the qualified callee name (std::system,
subprocess.run), keyword arguments (shell=True), the variable a call's result is assigned to (x = getenv(..)),
stream extraction (cin >> s), each function's parameters in order and its line span. This module collects those.
"""
from __future__ import annotations

import bisect
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

SRC = "{http://www.srcML.org/srcML/src}"
CPP = "{http://www.srcML.org/srcML/cpp}"
POS = "{http://www.srcML.org/srcML/position}"
FUNCS = {SRC + t for t in ("function", "constructor", "destructor")}


def _line(e: ET.Element) -> int:
    s = e.get(POS + "start")
    return int(s.split(":")[0]) if s else 0


def _end(e: ET.Element) -> int:
    s = e.get(POS + "end")
    return int(s.split(":")[0]) if s else 0


def _text(e: ET.Element) -> str:
    """The source text of a name element, without whitespace (std::system, self.conn.execute)."""
    return "".join(e.itertext()).replace(" ", "").replace("\n", "")


CONST = {SRC + "sizeof", SRC + "alignof", SRC + "typeof", SRC + "type"}


def _names(e: ET.Element) -> list[str]:
    """Identifier leaves in an expression (a name element with no name children), outside sizeof/alignof and
    type names, whose value does not depend on the variable's contents."""
    out = []

    def walk(x: ET.Element) -> None:
        if x.tag in CONST:
            return
        if x.tag == SRC + "name" and x.find(SRC + "name") is None and x.text and x.text.strip():
            out.append(x.text.strip())
        for c in x:
            walk(c)
    walk(e)
    return out


@dataclass
class Call:
    file: str
    function: str          # enclosing function name ("" at file level)
    line: int
    name: str              # qualified callee text, e.g. "std::system", "subprocess.run", "strcpy"
    args: list[list[str]]  # identifiers in each positional argument (1-based position = index + 1)
    kwargs: dict[str, str] = field(default_factory=dict)  # Python keyword arguments, name -> source text
    target: str | None = None  # variable the call's result is assigned to or initializes
    arg_texts: list[str] = field(default_factory=list)  # source text of each positional argument
    guards: set[str] = field(default_factory=set)   # names bounds-checked (<, <=, >, >=) by an enclosing if/while
    compared: bool = False      # the call's result is compared (getenv(..) != NULL), not stored
    jump_line: int = 0         # line of the first return/throw/exit (or no-return call) after it in its block

    @property
    def short(self) -> str:
        return self.name.replace("::", ".").split(".")[-1]


@dataclass
class Function:
    file: str
    name: str
    start: int
    end: int
    params: list[str]
    ptr_params: set[str] = field(default_factory=set)   # declared as pointer, reference or array: written through


@dataclass
class Region:
    """Statements control dependent on a predicate: a branch, loop body or case block, or the statements after an
    if whose branch leaves the block (if (!ok) return; ...)."""
    file: str
    function: str
    line: int                  # line of the predicate
    names: set[str]            # variables the predicate reads
    lines: set[int]            # start lines of the controlled statements


@dataclass
class Control:
    """A control statement, for control-flow edges between slice lines (srcSlice's controledges)."""
    file: str
    function: str
    kind: str                        # if, while, for, do, switch
    header: int                      # line of the (first) predicate
    branches: list[tuple[int, set[int]]]   # (predicate line, statement lines) of if / else if / loop body
    else_lines: set[int]
    end: int


@dataclass
class Index:
    calls: list[Call] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    extractions: list[tuple[str, str, int, str, str]] = field(default_factory=list)  # file, func, line, stream, var
    returns: dict[tuple[str, str], set[str]] = field(default_factory=dict)  # (file, func) -> names in return exprs
    regions: list[Region] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    exits: dict[str, set[int]] = field(default_factory=dict)   # file -> lines of return / throw statements
    languages: dict[str, str] = field(default_factory=dict)  # file -> srcML language
    # *p = e, *(p++) = e, *p++ = e: e's value is stored where p points (file, func, line, p, names in e). srcSlice
    # records no def of p on such a line, so the data written through a pointer would be lost.
    stores: list[tuple[str, str, int, str, list[str]]] = field(default_factory=list)
    # p = q in a for header (for (p = buf; ..)): srcSlice records no alias there (file, func, line, p, q)
    pointer_copies: list[tuple[str, str, int, str, str]] = field(default_factory=list)

    def function_at(self, file: str, line: int) -> Function | None:
        """The innermost function whose span holds the line (binary search over start lines)."""
        by_file = self.__dict__.get("_by_file")
        if by_file is None:
            by_file = {}
            for f in sorted(self.functions, key=lambda f: (f.start, -f.end)):
                by_file.setdefault(f.file, []).append(f)
            self._by_file = by_file
            self._starts = {k: [f.start for f in v] for k, v in by_file.items()}
        fs = by_file.get(file)
        if not fs:
            return None
        i = bisect.bisect_right(self._starts[file], line) - 1
        while i >= 0:                       # the latest start at or before the line that still contains it
            if fs[i].start <= line <= fs[i].end:
                return fs[i]
            i -= 1
            if i >= 0 and line - fs[i].end > 0 and all(g.end < line for g in fs[max(0, i - 3):i + 1]):
                break
        return None

    def functions_named(self, name: str) -> list[Function]:
        return [f for f in self.functions if f.name == name]


def _assign_target(expr_children: list[ET.Element], call: ET.Element) -> str | None:
    """In `x = f(..)` or `x += f(..)`, the name before the first assignment operator, if the call follows it."""
    for i, c in enumerate(expr_children):
        if c.tag == SRC + "operator" and (c.text or "").strip() in ("=", "+=", ":="):
            if any(call is d for k in expr_children[i + 1:] for d in k.iter()):
                left = [n for k in expr_children[:i] for n in _names(k)]
                return left[0] if left else None
            return None
    return None


# statements after which nothing later in the function runs (break, continue and goto only leave a loop or jump
# within the function, so code after them can still run)
JUMPS = {SRC + t for t in ("return", "throw", "raise")}
LEAVES = {SRC + t for t in ("return", "throw", "raise", "break", "continue", "goto")}   # leave the block
STMTS = {SRC + t for t in ("expr_stmt", "decl_stmt", "return", "break", "continue", "goto", "throw", "if_stmt",
                           "while", "for", "do", "switch", "case", "default", "try", "catch", "assert", "with",
                           "empty_stmt", "function_decl")}


def _stmt_lines(e: ET.Element) -> set[int]:
    return {_line(x) for x in e.iter() if x.tag in STMTS and _line(x)}


def _block(e: ET.Element) -> ET.Element | None:
    return e.find(SRC + "block")


def _leaves(block: ET.Element | None) -> bool:
    """The block's last statement leaves it: return, break, continue, goto, throw or a call that does not return."""
    if block is None:
        return False
    bc = block.find(SRC + "block_content")
    kids = [k for k in (list(bc) if bc is not None else list(block)) if k.tag in STMTS]
    if not kids:
        return False
    last = kids[-1]
    if last.tag in LEAVES:
        return True
    if last.tag == SRC + "expr_stmt":
        c = last.find(f"{SRC}expr/{SRC}call")
        n = c.find(SRC + "name") if c is not None else None
        return n is not None and (_text(n) in EXITS or bool(NORETURN.search(_text(n).strip("()*"))))
    return False


def _controls(fname: str, func_of, unit: ET.Element) -> list[Control]:
    out = []
    for e in unit.iter():
        if e.tag == SRC + "if_stmt":
            branches, els = [], set()
            for br in e:
                if br.tag == SRC + "if" and _block(br) is not None:
                    branches.append((_line(br), _stmt_lines(_block(br))))
                elif br.tag == SRC + "else" and _block(br) is not None:
                    els = _stmt_lines(_block(br))
            if branches:
                out.append(Control(fname, func_of(e), "if", branches[0][0], branches, els, _end(e)))
        elif e.tag in (SRC + "while", SRC + "for", SRC + "do", SRC + "switch"):
            b = _block(e)
            hdr = e.find(SRC + "condition") if e.tag != SRC + "for" else e.find(SRC + "control")
            if b is not None:
                h = _line(hdr) if hdr is not None else _line(e)
                out.append(Control(fname, func_of(e), e.tag[len(SRC):], h, [(h, _stmt_lines(b))], set(), _end(e)))
    return out


def _regions(fname: str, func_of, parent: dict, unit: ET.Element) -> list[Region]:
    out = []
    for e in unit.iter():
        fn = func_of(e)
        if e.tag == SRC + "if_stmt":
            conds: set[str] = set()
            has_else = e.find(SRC + "else") is not None
            for br in e:
                if br.tag == SRC + "if":
                    c = br.find(SRC + "condition")
                    conds = conds | set(_names(c)) if c is not None else conds
                    b = _block(br)
                    if b is not None:
                        out.append(Region(fname, fn, _line(br), set(conds), _stmt_lines(b)))
                    if not has_else and _leaves(b):    # if (!ok) return;  everything after depends on ok
                        blk = parent.get(e)
                        if blk is not None:
                            sib = list(blk)
                            after = set().union(*[_stmt_lines(x) for x in sib[sib.index(e) + 1:]] or [set()])
                            if after:
                                out.append(Region(fname, fn, _line(br), set(conds), after))
                elif br.tag == SRC + "else":
                    b = _block(br)
                    if b is not None:
                        out.append(Region(fname, fn, _line(br), set(conds), _stmt_lines(b)))
        elif e.tag in (SRC + "while", SRC + "do", SRC + "switch"):
            c = e.find(SRC + "condition")
            b = _block(e)
            if c is not None and b is not None:
                out.append(Region(fname, fn, _line(c), set(_names(c)), _stmt_lines(b)))
        elif e.tag == SRC + "for":
            c = e.find(SRC + "control")
            b = _block(e)
            if c is not None and b is not None:
                out.append(Region(fname, fn, _line(c), set(_names(c)), _stmt_lines(b)))
    return [r for r in out if r.names and r.lines]
EXITS = {"exit", "_exit", "abort", "sys.exit", "longjmp", "err", "errx"}
# calls that do not return, by naming convention: error(), fatal(), die(), panic(), exit_tcpdump(), ndo->ndo_error
NORETURN = re.compile(r"^(error|fatal|die|panic|abort|exit|bail)(_[a-z0-9]+)?$|[_.>](error|fatal|die|panic|abort)$",
                      re.I)


REL = {"<", "<=", ">", ">=", "&lt;", "&lt;=", "&gt;", "&gt;="}
CMP = REL | {"==", "!="}


def _guards(call: ET.Element, parent: dict) -> set[str]:
    out, e = set(), call
    while e in parent:
        e = parent[e]
        if e.tag in (SRC + "if", SRC + "while", SRC + "elseif"):
            cond = e.find(SRC + "condition")
            if cond is not None and any((o.text or "").strip() in REL for o in cond.iter(SRC + "operator")):
                out.update(_names(cond))
        if e.tag in FUNCS:
            break
    return out


def _compared(call: ET.Element, parent: dict) -> bool:
    """The call is an operand of a comparison: x = (getenv("A") != NULL) stores a truth value."""
    e = call
    while e in parent and parent[e].tag == SRC + "expr":
        sib = list(parent[e])
        if any(o.tag == SRC + "operator" and (o.text or "").strip() in CMP for o in sib):
            return True
        e = parent[e]
    return False


def _jump_line(call: ET.Element, parent: dict) -> int:
    """Line of the first later statement in the call's block that leaves the block (0 if none)."""
    stmt = call
    while stmt in parent and parent[stmt].tag not in (SRC + "block_content", SRC + "block", SRC + "unit"):
        stmt = parent[stmt]
    blk = parent.get(stmt)
    if blk is None:
        return 0
    later = list(blk)[list(blk).index(stmt) + 1:]
    for s in later:   # only statements of this block itself, not jumps nested in a later if
        if s.tag in JUMPS:
            return _line(s)
        if s.tag == SRC + "expr_stmt":
            c = s.find(f"{SRC}expr/{SRC}call")
            n = c.find(SRC + "name") if c is not None else None
            if n is not None and (_text(n) in EXITS or NORETURN.search(_text(n).strip("()*"))):
                return _line(s)
    return 0


def build(archive_xml: str) -> Index:
    idx = Index()
    root = ET.parse(archive_xml).getroot()
    units = root.findall(SRC + "unit") or [root]
    for unit in units:
        fname = unit.get("filename", "")
        idx.languages[fname] = unit.get("language", "")
        parent = {c: p for p in unit.iter() for c in p}

        def enclosing_function(e: ET.Element) -> ET.Element | None:
            while e in parent:
                e = parent[e]
                if e.tag in FUNCS:
                    return e
            return None

        def fname_of(fn: ET.Element | None) -> str:
            if fn is None:
                return ""
            n = fn.find(SRC + "name")
            return _text(n).replace("::", ".").split(".")[-1] if n is not None else ""

        for fn in unit.iter():
            if fn.tag not in FUNCS:
                continue
            plist = fn.find(SRC + "parameter_list")
            params, ptr_params = [], set()
            if plist is not None:
                for p in plist.findall(SRC + "parameter"):
                    decl = p.find(SRC + "decl")
                    n = decl.find(SRC + "name") if decl is not None else p.find(".//" + SRC + "name")
                    if n is not None:
                        pname = _names(n)[0] if _names(n) else _text(n)
                        params.append(pname)
                        mods = {(m.text or "").strip() for m in (decl.iter(SRC + "modifier") if decl is not None else [])}
                        if mods & {"*", "&", "&&"} or (n.find(SRC + "index") is not None):
                            ptr_params.add(pname)
            idx.functions.append(Function(fname, fname_of(fn), _line(fn), _end(fn), params, ptr_params))

        # object-like macros that rename a function: #define SYSTEM system, #define GETENV getenv
        alias = {}
        for d in unit.iter(CPP + "define"):
            m, v = d.find(f"{CPP}macro/{SRC}name"), d.find(CPP + "value")
            if m is not None and v is not None and d.find(f"{CPP}macro/{SRC}parameter_list") is None:
                val = "".join(v.itertext()).strip()
                if val.replace("_", "").replace(":", "").isalnum() and not val[:1].isdigit():
                    alias[_text(m)] = val

        for call in unit.iter(SRC + "call"):
            n = call.find(SRC + "name")
            if n is None:
                continue
            al = call.find(SRC + "argument_list")
            args, kwargs, arg_texts = [], {}, []
            for a in (al.findall(SRC + "argument") if al is not None else []):
                kids = list(a)
                # Python keyword argument: <argument><name>shell</name>=<expr>True</expr></argument>
                if (len(kids) >= 2 and kids[0].tag == SRC + "name" and kids[1].tag == SRC + "expr"
                        and (kids[0].tail or "").strip() == "="):
                    kwargs[_text(kids[0])] = _text(kids[1])
                    continue
                args.append([alias.get(x, x) for x in _names(a)])   # #define COMMAND_ARG3 data
                arg_texts.append(_text(a))
            # assignment target: declaration initializer or the left side of an assignment expression
            target, e = None, call
            while e in parent:
                p = parent[e]
                if p.tag == SRC + "expr" and parent.get(p) is not None and parent[p].tag == SRC + "init" \
                        and not _assign_target(list(p), call):
                    p = parent[p]
                if p.tag == SRC + "init":
                    decl = parent.get(p)
                    dn = decl.find(SRC + "name") if decl is not None else None
                    target = _names(dn)[0] if dn is not None and _names(dn) else None
                    break
                if p.tag == SRC + "expr" and parent.get(p) is not None and parent[p].tag in (
                        SRC + "expr_stmt", SRC + "return", SRC + "condition", SRC + "init"):
                    target = _assign_target(list(p), call)
                    break
                if p.tag in (SRC + "argument", SRC + "block", SRC + "block_content") or p.tag in FUNCS:
                    break
                e = p
            cname = _text(n)
            cname = alias.get(cname, cname)
            idx.calls.append(Call(fname, fname_of(enclosing_function(call)), _line(call), cname,
                                  args, kwargs, target, arg_texts, _guards(call, parent), _compared(call, parent),
                                  _jump_line(call, parent)))

        idx.regions += _regions(fname, lambda e: fname_of(enclosing_function(e)), parent, unit)
        idx.controls += _controls(fname, lambda e: fname_of(enclosing_function(e)), unit)
        idx.exits[fname] = {_line(x) for x in unit.iter() if x.tag in JUMPS and _line(x)}

        for r in unit.iter(SRC + "return"):
            fn = enclosing_function(r)
            if fn is not None:
                idx.returns.setdefault((fname, fname_of(fn)), set()).update(_names(r))

        # C++ delete / delete[] as a pseudo-call "delete" with the deleted expression as its argument
        for ex in unit.iter(SRC + "expr"):
            kids = list(ex)
            if kids and kids[0].tag == SRC + "operator" and (kids[0].text or "").strip() == "delete":
                rest = [k for k in kids[1:] if k.tag != SRC + "index" and (k.text or "").strip() not in ("(", ")")]
                if rest:
                    txt = "".join("".join(k.itertext()) for k in rest).replace(" ", "")
                    idx.calls.append(Call(fname, fname_of(enclosing_function(ex)), _line(ex), "delete",
                                          [_names(rest[0])], {}, None, [txt], set(), False,
                                          _jump_line(ex, parent)))

        # stores through a pointer, and pointer copies in for headers
        for ex in unit.iter(SRC + "expr"):
            st = parent.get(ex)
            if st is None or st.tag not in (SRC + "expr_stmt", SRC + "init"):
                continue
            kids = list(ex)
            eq = next((i for i, k in enumerate(kids) if k.tag == SRC + "operator" and (k.text or "").strip() == "="),
                      None)
            if eq is None or eq == 0:
                continue
            lhs, rhs = kids[:eq], kids[eq + 1:]
            if any(k.tag == SRC + "call" for k in rhs):
                continue                                    # calls are propagators or returns, handled elsewhere
            fn = fname_of(enclosing_function(ex))
            lnames = [n for k in lhs for n in _names(k)]
            rnames = [n for k in rhs for n in _names(k)]
            if lhs[0].tag == SRC + "operator" and (lhs[0].text or "").strip() == "*" and lnames and rnames:
                idx.stores.append((fname, fn, _line(ex), lnames[0], rnames))
            elif st.tag == SRC + "init" and parent.get(parent.get(st)) is not None \
                    and parent[parent[st]].tag == SRC + "for" and len(lhs) == 1 and lhs[0].tag == SRC + "name" \
                    and len(rhs) == 1 and rhs[0].tag == SRC + "name" and len(lnames) == 1 and len(rnames) == 1:
                idx.pointer_copies.append((fname, fn, _line(ex), lnames[0], rnames[0]))

        # stream extraction: cin >> a >> b
        for ex in unit.iter(SRC + "expr"):
            kids = list(ex)
            for i, k in enumerate(kids):
                if k.tag == SRC + "operator" and (k.text or "").strip() == ">>" and i > 0:
                    left = _text(kids[0]) if kids[0].tag == SRC + "name" else ""
                    if left.split("::")[-1] in ("cin", "wcin") and i + 1 < len(kids):
                        for v in _names(kids[i + 1])[:1]:
                            idx.extractions.append((fname, fname_of(enclosing_function(ex)), _line(ex),
                                                    left, v))
    return idx

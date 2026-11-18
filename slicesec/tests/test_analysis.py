"""Expected results on small programs whose flows were checked by hand. Needs srcml and srcslice on PATH.
Run from tool/slicesec:  python3 -m unittest discover -s tests -v
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from slicesec.analysis import analyze

FIX = Path(__file__).parent / "fixtures"
CACHE = Path(tempfile.mkdtemp(prefix="slicesec-test-"))


def found(a):
    return {(f.cwe, f.file, f.line) for f in a.findings()}


class C(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(FIX / "c", CACHE)

    def test_findings(self):
        self.assertEqual(found(self.a), {
            ("CWE-120", "flows.c", 6),     # strcpy(line, cmd), cmd from fgets via run(buf)
            ("CWE-78", "flows.c", 7),      # system(line), through the strcpy copy
            ("CWE-416", "flows.c", 17),    # printf(.., q) after free(p), q = p
            ("CWE-242", "vuln.c", 9), ("CWE-242", "vuln.c", 17), ("CWE-242", "vuln.c", 25),   # gets
            ("CWE-120", "vuln.c", 10),     # strcpy(output, buf), buf from gets
            ("CWE-416", "vuln.c", 19),     # printf(.., data) after free(data)
        })

    def test_interprocedural_path(self):
        f = next(f for f in self.a.findings() if f.cwe == "CWE-78")
        self.assertEqual([(s.var, s.line, s.how) for s in f.path],
                         [("buf", 12, "source: fgets()"), ("cmd", 15, "passed to run()"), ("line", 6, "copy"),
                          ("line", 7, "sink: system argument 1")])

    def test_sanitizer_stops_taint_not_slice(self):
        sl = self.a.forward_slice(self.a.find_var("flows.c", 12, "buf"))
        self.assertIn(17, sl["lines"]["flows.c"])               # n = atoi(buf) is printed on line 17
        self.assertIn({"file": "flows.c", "function": "main", "var": "n"}, sl["variables"])
        self.assertFalse(any(f.line == 17 and f.cwe == "CWE-134" for f in self.a.findings()))

    def test_slice_crosses_call(self):
        sl = self.a.forward_slice(self.a.find_var("flows.c", 12, "buf"))
        self.assertTrue({4, 6, 7} <= set(sl["lines"]["flows.c"]))   # run's parameter and its uses


class Python(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(FIX / "py", CACHE)

    def test_findings(self):
        self.assertEqual(found(self.a), {("CWE-78", "flows.py", 4), ("CWE-22", "flows.py", 9),
                                         ("CWE-78", "flows.py", 11)})

    def test_library_call_not_followed_into_local_function(self):
        # subprocess.run(data) must not be linked to the local def run(cmd)
        data = ("flows.py", "main", "data")
        self.assertFalse(any(b[1] == "run" for b, _, _ in self.a.edges.get(data, [])))


class Mixed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(FIX / "mixed", CACHE)

    def test_findings(self):
        self.assertEqual(found(self.a), {("CWE-78", "g.cpp", 6),    # std::cin >> s, sh.exec(s), std::system
                                         ("CWE-78", "g.cpp", 15),   # getenv, alias, system
                                         ("CWE-89", "k.py", 7)})    # request arg into a method's SQL string

    def test_python_method_self_offset(self):
        f = next(f for f in self.a.findings() if f.cwe == "CWE-89")
        self.assertEqual(f.path[1].var, "user")


class Example(unittest.TestCase):
    """The walkthrough program: recv into an output parameter, four files to popen; free then log."""
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(FIX / "example", CACHE)

    def test_findings(self):
        self.assertEqual(found(self.a), {("CWE-78", "report.c", 17), ("CWE-416", "log.c", 6)})

    def test_path(self):
        f = next(f for f in self.a.findings() if f.cwe == "CWE-78")
        self.assertEqual([(s.file, s.line, s.var) for s in f.path],
                         [("net.c", 8, "req"), ("main.c", 9, "host"), ("main.c", 14, "host"), ("report.c", 16, "host"),
                          ("report.c", 8, "cmd"), ("report.c", 16, "cmd"), ("report.c", 17, "cmd")])


class Control(unittest.TestCase):
    """Control dependence from srcML structure (srcSlice has none)."""
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(FIX / "control", CACHE)

    def lines(self, var):
        return set(self.a.forward_slice(self.a.find_var("control.c", 1, var))["lines"]["control.c"])

    def test_branches_loops_and_switch(self):
        # x controls the if branch (4), the else-if and else (6, 7), the for body (9) and the switch (10)
        self.assertTrue({4, 6, 7, 9, 10} <= self.lines("x"))

    def test_after_an_early_return(self):
        # if (!y) return;  the statements after it (12, 13) depend on y
        self.assertTrue({12, 13} <= self.lines("y"))

    def test_taint_does_not_follow_control_by_default(self):
        d = Path(tempfile.mkdtemp())
        (d / "t.c").write_text("void f(){ char *e = getenv(\"X\");\n char c[9]; int ok = 0;\n"
                               " if (e[0] == 'a')\n  ok = 1;\n sprintf(c, \"%d\", ok);\n system(c); }")
        self.assertEqual(found(analyze(d, CACHE)), set())
        self.assertEqual(found(analyze(d, CACHE, implicit=True)), {("CWE-120", "t.c", 5), ("CWE-78", "t.c", 6)})


@unittest.skipUnless(shutil.which("srcptr"), "srcptr (the sliceSec fork) not installed")
class PointsTo(unittest.TestCase):
    def test_alias_through_an_output_parameter(self):
        # n gets m's heap object inside take(); only srcPtr's points-to sets show that n and m alias
        d = Path(tempfile.mkdtemp())
        (d / "t.c").write_text("#include <stdlib.h>\nvoid take(char **dst, char *src)\n{\n    *dst = src;\n}\n"
                               "void f(void)\n{\n    char *m = malloc(8);\n    char *n;\n    take(&n, m);\n"
                               "    free(m);\n    n[0] = 1;\n}\n")
        a = analyze(d, CACHE)
        self.assertTrue(a.pts.get(("t.c", "f", "n")))
        self.assertIn(("CWE-416", "t.c", 12), found(a))


class ControlFlowPaths(unittest.TestCase):
    """srcSlice's controledges on the example of Fig. 2 in Alomari et al., JSEP 2014."""
    @classmethod
    def setUpClass(cls):
        cls.a = analyze(FIX / "jsep", CACHE)

    def edges(self, var):
        own = set(self.a.own_lines(("fig2.c", "main", var)))
        return {(x, y) for x, y, _ in self.a.control_edges("fig2.c", "main", own)}

    def test_profile_edges_as_in_the_paper(self):
        self.assertEqual(self.edges("sum"), {(2, 5), (2, 8), (5, 8)})
        self.assertEqual(self.edges("i"), {(3, 4), (4, 5), (4, 9), (5, 6), (6, 9)})

    def test_complete_slice_as_in_the_paper(self):
        sl = self.a.forward_slice(("fig2.c", "main", "i"))
        self.assertEqual(sl["lines"]["fig2.c"], [3, 4, 5, 6, 8, 9])
        kinds = {(e["from"], e["to"]): e["kind"] for e in sl["controlEdges"]["fig2.c"]}
        self.assertEqual((kinds[(4, 5)], kinds[(4, 8)]), ("true", "false"))


class Precision(unittest.TestCase):
    def check(self, code: str, name: str = "t.c"):
        d = Path(tempfile.mkdtemp())
        (d / name).write_text(code)
        return found(analyze(d, CACHE))

    def test_member_free_is_not_object_free(self):
        self.assertEqual(self.check("void f(struct s *p){ free(p->buf); p->n = 0; }"), set())

    def test_free_then_noreturn_error(self):
        self.assertEqual(self.check(
            "void f(char *p){ if (!p) { free(p); error(\"x\"); } p[0] = 0; }"), set())

    def test_alias_after_free_is_not_alias(self):
        self.assertEqual(self.check(
            "void f(struct n *cur){ struct n *prev; while (cur) { prev = cur->prev; free(cur); cur = prev; } }"), set())

    def test_bounds_checked_length(self):
        body = "void f(char *d, char *s, FILE *fp){ int n;\n fread(&n, 4, 1, fp);\n %s }"
        self.assertEqual(self.check(body % "memcpy(d, s, n);"), {("CWE-805", "t.c", 3)})     # unguarded: reported
        self.assertEqual(self.check(body % "if (n < 8) memcpy(d, s, n);"), set())            # guarded: not

    def test_compared_source_is_a_truth_value(self):
        self.assertEqual(self.check(
            "void f(){ int c = (getenv(\"X\") != 0); printf(c ? \"a\" : \"b\"); }"), set())

    def test_sscanf_propagates_but_is_not_a_source(self):
        self.assertEqual(self.check("void f(char *s, char *d){ int v; sscanf(s, \"%d\", &v); memcpy(d, s, v); }"),
                         set())
        self.assertEqual(self.check(
            "void f(char *d){ char s[9]; int v; fgets(s, 9, stdin);\n sscanf(s, \"%d\", &v); memcpy(d, s, v); }"),
            {("CWE-805", "t.c", 2)})

    def test_break_does_not_end_the_function(self):
        # Juliet flow variant 16: the free is left by break, and the pointer is freed again after the loop
        self.assertEqual(self.check(
            "void f(){ char *d = malloc(9);\n while (1) { free(d); break; }\n free(d); }"), {("CWE-415", "t.c", 3)})

    def test_static_helper_in_own_file(self):
        # two files each define static helper(); the call in a.c must go to a.c's helper only
        d = Path(tempfile.mkdtemp())
        (d / "a.c").write_text("static void helper(char *p)\n{\n    free(p);\n}\n"
                               "void fa()\n{\n    char *p = malloc(4);\n    free(p);\n    helper(p);\n}\n")
        (d / "b.c").write_text("static void helper(char *p)\n{\n    (void)0;\n}\n"
                               "void fb()\n{\n    char *q = malloc(4);\n    free(q);\n    helper(q);\n}\n")
        self.assertEqual(found(analyze(d, CACHE)), {("CWE-415", "a.c", 3)})

    def test_sizeof_is_not_a_tainted_length(self):
        self.assertEqual(self.check(
            "void f(char *d){ char s[9]; fgets(s, 9, stdin); memcpy(d, s, sizeof(s)); }"), set())


if __name__ == "__main__":
    unittest.main()

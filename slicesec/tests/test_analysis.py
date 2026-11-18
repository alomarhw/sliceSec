"""Expected results on small programs whose flows were checked by hand. Needs srcml and srcslice on PATH.
Run from tool/slicesec:  python3 -m unittest discover -s tests -v
"""
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

    def test_sizeof_is_not_a_tainted_length(self):
        self.assertEqual(self.check(
            "void f(char *d){ char s[9]; fgets(s, 9, stdin); memcpy(d, s, sizeof(s)); }"), set())


if __name__ == "__main__":
    unittest.main()

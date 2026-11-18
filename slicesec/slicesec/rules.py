"""Sources, propagators, sanitizers and sinks. Small on purpose: every entry is a documented library function.

Positions are 1-based argument positions. For Python, names are matched against the qualified call text
(subprocess.run) or, where marked "*.", against any receiver (cursor.execute).
"""
from __future__ import annotations

from dataclasses import dataclass

# ---- C and C++ -------------------------------------------------------------------------------------------
# functions that write untrusted data into an argument
C_SOURCE_ARGS = {"gets": [1], "fgets": [1], "fgetws": [1], "fread": [1], "read": [2], "recv": [2],
                 "recvfrom": [2], "getline": [1], "scanf": "rest2", "fscanf": "rest3"}
# functions whose return value is untrusted
C_SOURCE_RETURNS = {"getenv", "secure_getenv", "fgetc", "getc", "getchar"}
# copy data from one argument into another (src -> dst)
C_PROPAGATORS = {"strcpy": (2, 1), "strncpy": (2, 1), "strcat": (2, 1), "strncat": (2, 1), "memcpy": (2, 1),
                 "memmove": (2, 1), "sprintf": ("rest3", 1), "snprintf": ("rest4", 1), "wcscpy": (2, 1),
                 "wcscat": (2, 1), "strdup": (1, 0), "strndup": (1, 0),     # 0 = the return value
                 "sscanf": (1, "rest3")}                                    # parses arg 1 into args 3..
# functions whose result is not attacker controlled text any more
C_SANITIZERS = {"atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "atof", "abs",
                "strlen", "sizeof"}


@dataclass(frozen=True)
class Sink:
    rule: str
    cwe: str
    names: tuple[str, ...]
    args: tuple[int, ...] | str    # dangerous positions, or "rest<k>" for k and later
    message: str
    severity: str = "error"
    kw: tuple[str, str] | None = None   # Python: required keyword argument, e.g. ("shell", "True")


C_SINKS = [
    Sink("cmd-injection", "CWE-78", ("system", "popen", "_popen", "_wpopen", "_wsystem"), (1,),
         "untrusted data reaches a command interpreter"),
    Sink("cmd-injection", "CWE-78", ("execl", "execlp", "execle", "execv", "execvp", "execvpe", "_execl", "_execlp",
                                     "_execv", "_execvp", "_wexecl", "_wexeclp", "_wexecv", "_wexecvp"), "rest1",
         "untrusted data reaches a program's command line"),
    Sink("unbounded-copy", "CWE-120", ("strcpy", "strcat", "wcscpy", "wcscat"), (2,),
         "untrusted data is copied without a bound"),
    Sink("unbounded-copy", "CWE-120", ("sprintf", "vsprintf"), "rest3",
         "untrusted data is formatted into a buffer without a bound"),
    Sink("tainted-length", "CWE-805", ("memcpy", "memmove", "strncpy", "strncat", "memset"), (3,),
         "an untrusted value is used as a copy length"),
    Sink("format-string", "CWE-134", ("printf", "vprintf", "wprintf"), (1,),
         "untrusted data is used as a format string"),
    Sink("format-string", "CWE-134", ("fprintf", "sprintf", "vfprintf", "vsprintf", "syslog", "fwprintf"), (2,),
         "untrusted data is used as a format string"),
    Sink("format-string", "CWE-134", ("snprintf", "vsnprintf"), (3,),
         "untrusted data is used as a format string"),
]
C_ALWAYS = {"gets": ("dangerous-function", "CWE-242", "gets cannot limit its input; use fgets")}
C_FREE = {"free", "kfree", "g_free", "cfree", "delete"}

# ---- Python ----------------------------------------------------------------------------------------------
PY_SOURCE_RETURNS = {"input", "raw_input", "os.getenv", "os.environ.get", "sys.stdin.readline", "sys.stdin.read",
                     "*.args.get", "*.form.get", "*.values.get", "*.cookies.get", "*.headers.get", "*.get_json",
                     "*.recv", "urllib.parse.unquote"}
PY_SANITIZERS = {"int", "float", "bool", "len", "shlex.quote", "pipes.quote", "html.escape", "os.path.basename",
                 "secure_filename", "werkzeug.utils.secure_filename"}
PY_SINKS = [
    Sink("cmd-injection", "CWE-78", ("os.system", "os.popen", "commands.getoutput", "subprocess.getoutput",
                                     "subprocess.getstatusoutput"), (1,),
         "untrusted data reaches a shell command"),
    Sink("cmd-injection", "CWE-78", ("subprocess.run", "subprocess.call", "subprocess.Popen",
                                     "subprocess.check_call", "subprocess.check_output"), (1,),
         "untrusted data reaches a shell command (shell=True)", kw=("shell", "True")),
    Sink("code-injection", "CWE-95", ("eval", "exec"), (1,), "untrusted data is evaluated as code"),
    Sink("sql-injection", "CWE-89", ("*.execute", "*.executemany", "*.executescript", "*.raw"), (1,),
         "an SQL statement is built from untrusted data"),
    Sink("path-traversal", "CWE-22", ("open", "io.open", "os.open", "os.remove", "os.unlink", "shutil.rmtree",
                                      "send_file", "flask.send_file"), (1,),
         "an untrusted path is opened", severity="warning"),
]


def name_matches(call_name: str, patterns) -> bool:
    n = call_name.replace("::", ".")
    for p in patterns:
        if p.startswith("*."):
            if n.endswith(p[1:]) or n == p[2:]:
                return True
        elif "." in p:
            if n == p:
                return True
        elif n == p or n.split(".")[-1] == p and n.split(".")[0] in ("std", "", "self") or n == "std." + p:
            return True
    return False


def positions(spec, nargs: int) -> list[int]:
    if isinstance(spec, str) and spec.startswith("rest"):
        return list(range(int(spec[4:]), nargs + 1))
    return [k for k in spec if k <= nargs]

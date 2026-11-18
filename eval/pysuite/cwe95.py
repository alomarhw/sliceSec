"""CWE-95 cases: eval/exec of untrusted input."""
import ast


def bad_eval():
    expr = input()
    return eval(expr)


def bad_exec_env():
    import os
    code = os.environ.get("HOOK")
    exec(code)


def bad_sink_calc(e):
    return eval(e)


def bad_interprocedural():
    s = input()
    return bad_sink_calc(s)


def good_literal_eval():
    expr = input()
    return ast.literal_eval(expr)


def good_constant():
    return eval("1 + 2")


def good_sink_calc(e):
    return eval(e)


def good_interprocedural():
    return good_sink_calc("2 ** 10")


def good_float():
    x = float(input())
    return eval("%f * 2" % x)

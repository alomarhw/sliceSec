"""CWE-78 cases: bad_* functions pass untrusted input to a shell, good_* functions do not."""
import os
import shlex
import subprocess


def bad_system():
    name = input()
    os.system("ls " + name)


def bad_popen_env():
    d = os.getenv("TARGET_DIR")
    os.popen("du -sh " + d)


def bad_subprocess_shell():
    host = input()
    cmd = "ping -c 1 " + host
    subprocess.run(cmd, shell=True)


def bad_sink_run(c):
    os.system(c)


def bad_interprocedural():
    arg = input()
    bad_sink_run("echo " + arg)


def bad_check_output():
    q = input()
    subprocess.check_output("grep " + q + " log.txt", shell=True)


def good_constant():
    os.system("ls -l")


def good_list_args():
    host = input()
    subprocess.run(["ping", "-c", "1", host])


def good_quoted():
    name = input()
    os.system("ls " + shlex.quote(name))


def good_int():
    n = int(input())
    os.system("head -n %d log.txt" % n)


def good_sink_run(c):
    os.system(c)


def good_interprocedural():
    good_sink_run("echo hello")

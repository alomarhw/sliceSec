"""CWE-22 cases: files opened by an untrusted path."""
import os


def bad_open():
    name = input()
    with open("/srv/files/" + name) as f:
        return f.read()


def bad_remove(request):
    p = request.args.get("file")
    os.remove(os.path.join("/tmp", p))


def bad_sink_read(path):
    return open(path).read()


def bad_interprocedural():
    n = input()
    return bad_sink_read("/data/" + n)


def good_basename():
    name = os.path.basename(input())
    with open("/srv/files/" + name) as f:
        return f.read()


def good_constant():
    return open("/etc/hostname").read()


def good_sink_read(path):
    return open(path).read()


def good_interprocedural():
    return good_sink_read("/data/index.html")

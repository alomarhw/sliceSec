"""CWE-89 cases: SQL built from untrusted input."""
import sqlite3


def bad_concat():
    conn = sqlite3.connect("db.sqlite")
    user = input()
    conn.execute("SELECT * FROM users WHERE name = '" + user + "'")


def bad_format(request):
    cur = sqlite3.connect("db.sqlite").cursor()
    uid = request.args.get("id")
    q = "DELETE FROM items WHERE id = %s" % uid
    cur.execute(q)


class Repo:
    def __init__(self):
        self.conn = sqlite3.connect("db.sqlite")

    def bad_sink_find(self, name):
        return self.conn.execute("SELECT * FROM t WHERE n = '%s'" % name)

    def good_sink_find(self, name):
        return self.conn.execute("SELECT * FROM t WHERE n = ?", (name,))


def bad_interprocedural(request):
    r = Repo()
    return r.bad_sink_find(request.form.get("n"))


def good_param():
    conn = sqlite3.connect("db.sqlite")
    user = input()
    conn.execute("SELECT * FROM users WHERE name = ?", (user,))


def good_interprocedural(request):
    r = Repo()
    return r.good_sink_find(request.form.get("n"))


def good_int(request):
    cur = sqlite3.connect("db.sqlite").cursor()
    uid = int(request.args.get("id"))
    cur.execute("DELETE FROM items WHERE id = %d" % uid)

import sqlite3
class Repo:
    def __init__(self, db):
        self.conn = sqlite3.connect(db)
    def find(self, user):
        q = "SELECT * FROM t WHERE u='%s'" % user
        return self.conn.execute(q)
def handler(req):
    u = req.args.get("u")
    r = Repo("x.db")
    return r.find(u)

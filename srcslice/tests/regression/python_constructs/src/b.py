import os

def g(a, b=0):
    return a

class K:
    def m(self, v):
        w = v + 1
        return w

    def caller(self, z):
        q = self.m(z)
        return q

def p_kw(x):
    r = g(x, b=x)
    return r

def p_kwonly(x):
    r = g(a=x)
    return r

def p_for(items):
    total = 0
    for it in items:
        total = total + g(it)
    return total

def p_with(path):
    with open(path) as fh:
        data = fh.read()
    return data

def p_tuple(x, y):
    a, b = g(x), g(y)
    return a + b

def p_aug(x):
    acc = 0
    acc += g(x)
    return acc

def p_method_arg(x):
    s = K()
    t = s.m(x)
    return t

def p_attr_arg(obj):
    u = g(obj.field)
    return u

def p_star(*args, **kw):
    v = g(*args, **kw)
    return v

def p_compr(xs):
    ys = [g(e) for e in xs]
    return ys

def p_fstring(x):
    msg = f"value {g(x)}"
    return msg

def p_lambda(x):
    h = lambda k: g(k)
    return h(x)

def p_while(x):
    while g(x):
        x = x - 1
    return x

def p_global():
    return os.path.join("a", "b")

def outer(a):
    def inner(b):
        return g(b)
    r = inner(a)
    return g(r)

def loads(s, *, cls=None, object_hook=None):
    return s

def use_loads(t, hook):
    return loads(t, object_hook=hook)

def kwcall(x):
    return h(options=g(x))

top = g(outer)
def raises(x):
    raise ValueError(x)

def yields(x):
    yield g(x)

def receiver(fp):
    return loads(fp.read())

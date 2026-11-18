def a1(x: int):
    return g(x)

def a2(x: int = 0, y=None):
    return g(x, y)

def a3(self, *, limit: int | None = None):
    return g(limit)

@property
def a4(self):
    return g(self)

async def a5(path):
    return await g(path)

def a6(x) -> str:
    return g(x)

class C:
    def a7(self, key: str, value: "list[int]") -> None:
        g(key, value)

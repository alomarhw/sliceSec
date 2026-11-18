# The enhanced srcSlice used by sliceSec

This folder is srcSlice ([srcML/srcSlice](https://github.com/srcML/srcSlice), GPL-3.0) at upstream commit
`ce86ef8`, plus two commits that make its slice profiles accurate enough for the security extension. The upstream
submodules are vendored at their pinned commits:
- `src/srcSAX` at `daf85a8`;
- `srcSAXEventDispatch` at `6b2eae3`, with its own `srcSAX` at `d4cb7e3`.

## Changes over upstream

**`99b09e3`: call sites, scoping and output (C, C++, C#, Java), plus Python**
- Call arguments are linked in every statement: `return`, `if`/`while`/`for`/`switch` headers, `throw` and
  `yield`. Before, only declarations and expression statements were linked.
- Each nested call has its own argument counter, so `f(y, g(x))` gives `g{1}`.
- `sizeof`, `alignof`, `typeof` and `decltype` create no links.
- A member name after `.` or `->` is not a local variable.
- A call no longer overwrites a variable's parameter index, so interprocedural slicing follows the k-th parameter.
- `return x;` no longer leaks into the next assignment.
- `int r = f(x)` makes `r` depend on `x`, as `r = f(x)` does.
- Compound assignment is an assignment that also uses its left-hand side.
- Nested functions get their own scope.
- Callee names never contain whitespace, so every profile is printed on one line.
- `--help` and `--version` work, and malformed input exits with status 1.
- Python (srcML 1.1):
  - keyword arguments map to the named parameter;
  - `obj.m(x)` skips `self`/`cls`;
  - `for`, comprehension, `with` and tuple targets are bound;
  - annotations, lambdas and f-string fields are handled.

**`f25dc5f`: subscripts and module variables**
- A name inside a subscript is a use of that variable (`q[a]`), and the assigned variable depends on it.
- A read inside a function falls back to the file-scope variable of that name (a Python module variable).

## Build

```
cmake -S srcslice -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build -j 8
cp build/bin/srcSlice /usr/local/bin/srcslice     # sliceSec calls `srcslice`
```

The CMake policy flag is needed with CMake 4. Regression tests (122 checks):
`tests/regression/run.sh build/bin/srcSlice srcml`.

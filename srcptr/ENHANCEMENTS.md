# The extended srcPtr used by sliceSec

This folder is srcPtr ([srcML/srcPtr](https://github.com/srcML/srcPtr), GPL-3.0; Zyrianov et al., ICPC 2019) at
upstream commit `e1cbc49`, with the changes below. srcSAX and srcSAXEventDispatch are vendored.

## Accuracy fixes
- **Variable identity.** Variables are identified by file, declaration line and name. Upstream ordered them by name
  only, so every variable called `p` in a program shared one points-to set.
- **Copy bug.** `isStatic` was copied from `isPointer`; it is now copied from `isStatic`.
- **Scoping.** Each function's parameters get their own scope frame. Before, a later function's parameter `p`
  resolved to an earlier function's `p`.
- **Objects.** Arrays used as pointers, allocation sites (`malloc`, `calloc`, `realloc`, `strdup`, `new`, ...) and
  function names are objects, alongside `&x`.
- **Loads and stores.** Loads and stores through `*`, `->`, `.` and `[]` are modeled (field-insensitive): `q = *p`,
  `*p = q`, `p->f = q`, `q = p[i]`.
- **Arguments.** Call arguments are paired with parameters by position and keep their `&`. Before, every name inside
  an argument shifted the position.
- **Returns.** `return` statements bind to a return node per function, for functions that return a pointer, and
  `x = f(..)` reads it.
- **Casts.** Cast type names on the right-hand side are skipped.
- **Andersen's solver.** It is a worklist solver with difference propagation. Upstream recursed to a fixed depth
  and cleared its queue, so its result depended on statement order, and it had no loads or stores. On libtiff the
  new solver takes 5.8 s, against 92.6 s for a naive fixed point.
- **srcSAXEventDispatch:**
  - `return` is a parser state;
  - unit attributes are matched by name (the file name was read from a fixed position);
  - a function's return type is no longer taken from pointer declarations inside its body.
- **Build.** `CLI11.hpp` is no longer passed to the linker.

## Output
`srcptr -i archive.xml -a --tsv` prints one fact per line, in eight tab-separated columns: the file, line, name and
kind of the pointer, then of the object. Kinds are `var`, `heap`, `function` and `ret`. `--max-pointers N` leaves out
objects that more than N variables point to (sliceSec passes 20), and the TSV is printed from integer ids.

## Effect
On tcpdump (245 files), upstream srcPtr reports 4 points-to facts among the 614 pointers it lists. This version
reports 4,224 facts in about 2.4 s.

## Build and test
```
cmake -S srcptr -B build-ptr -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build-ptr -j 8
cp build-ptr/bin/srcptr /usr/local/bin/srcptr     # sliceSec runs `srcptr` when it is on PATH
tests/regression/run.sh build-ptr/bin/srcptr srcml # 3 programs, 24 exact facts
```

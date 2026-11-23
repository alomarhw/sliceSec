# sliceSec

sliceSec shows forward slices, taint paths and vulnerability findings for C, C++ and Python in Visual Studio Code.
The slices come from [srcSlice](https://github.com/srcML/srcSlice), and the code is parsed by
[srcML](https://www.srcml.org).

- **Forward slice of the variable under the cursor.** It follows calls across functions and files, highlights the
  slice in every open editor, and lists it in the *Slice and Taint Path* view.
- **Taint path.** It shows the chain of variables and calls from an untrusted source (`recv`, `fgets`, `getenv`,
  `argv`, `input()`, web request arguments, ...) to the variable under the cursor. Each step is numbered in the
  editor.
- **Findings in the Problems panel.** Each finding carries its path as clickable related locations.
  - C/C++: command injection (CWE-78), unbounded copy (CWE-120), tainted length (CWE-805), format string (CWE-134),
    use after free (CWE-416), double free (CWE-415), `gets` (CWE-242).
  - Python: command injection (CWE-78), `eval`/`exec` (CWE-95), SQL injection (CWE-89), path traversal (CWE-22).
- **Hover.** It shows the variable's srcSlice profile: defs, uses, the variables it flows into, aliases and calls.
- **The same engine on the command line.** Output can be text, JSON or SARIF, for continuous integration.

The code being analyzed is never compiled or run, so code that does not build can still be analyzed.

## Install

1. Install srcML 1.1 (`brew install srcml`, or see srcml.org).
2. Build the enhanced srcSlice in `srcslice/` (see `srcslice/ENHANCEMENTS.md`):
   ```
   cmake -S srcslice -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
   cmake --build build -j 8
   cp build/bin/srcSlice /usr/local/bin/srcslice
   ```
3. Optional, for pointer analysis: build the extended srcPtr in `srcptr/` (see `srcptr/ENHANCEMENTS.md`) and put
   `srcptr` on `PATH`. Without it, aliases come from srcSlice's pointer copies only.
4. Install the extension. Download `slicesec-0.2.1.vsix` from the
   [Releases page](https://github.com/alomarhw/sliceSec/releases) and run
   `code --install-extension slicesec-0.2.1.vsix`, or in VS Code use *Extensions > ... > Install from VSIX*.
   The analysis package is inside the `.vsix`. It needs Python 3.10 or later as `python3` on `PATH`, or set
   `slicesec.pythonPath`.
5. Optional, for the command line: `pip install ./slicesec` (no dependencies). To build the `.vsix` yourself, run
   `extension/package.sh`.

## Layout

| Folder | Contents |
|---|---|
| `extension/` | The VS Code extension, which talks to the analysis over JSON-RPC on stdio |
| `slicesec/` | The analysis package, the command line `slicesec`, and its tests (`python3 -m unittest discover -s tests`) |
| `srcslice/` | The enhanced srcSlice, with srcSAX vendored |
| `srcptr/` | The extended srcPtr (Andersen points-to analysis on srcML), with its dependencies vendored |
| `eval/` | The paper's evaluation: Juliet, the Python check, speed, the walkthrough example and Fig. 2 |

## Command line

```
slicesec scan path/to/project                    # findings with their paths
slicesec scan path/to/project --format sarif     # for CI (add --fail-on-findings)
slicesec slice path/to/project main.c 8 host     # forward slice of host at main.c:8
```

## How it works

1. srcML turns the workspace into one archive.
2. srcSlice computes a slice profile for every variable.
3. A second pass over the srcML adds what the profiles leave out: qualified callee names, keyword arguments,
   assignment targets, parameters, returns and bounds checks.
4. srcSlice folds each callee's facts into its callers. sliceSec keeps only the facts that the source line confirms,
   and takes calls from the call sites, so every edge of its data-flow graph is one real step.
5. Control dependence comes from the srcML structure: branches, loop bodies, `switch` cases and the statements
   after an early exit. Forward slices follow it. Taint follows data only.
6. Points-to sets come from srcPtr, and two pointers in one function that may point to the same object are aliases.
7. Taint is searched breadth first from all sources at once, with a hop limit (6 by default).

The paper has the details.

## Evaluation

`eval/` holds the scripts and outputs behind the paper's numbers:
- Juliet C/C++ 1.3 against flawfinder and Cppcheck;
- a Python check against Bandit;
- timings on open-source projects.

## License

GPL-3.0.

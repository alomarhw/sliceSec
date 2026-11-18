# Evaluation

These are the scripts and outputs behind the numbers in the paper. The evaluated version is tag `v1-eval`.
`CHANGES.md` lists the fixes made since then.

## Juliet C/C++ 1.3: CWE-78, 134, 415 and 416

- **Script and outputs:** `juliet_eval.py` writes `juliet_eval.txt` and `juliet_eval.json`. `juliet_misses.py`
  writes `juliet_misses.txt`, which groups the misses.
- **Data:** Juliet 1.3 for C/C++ from NIST SARD. Point `JULIET_DIR` at its `C/testcases`.
- **Tools on `PATH`:** srcml 1.1, srcslice (from `../srcslice`), flawfinder 2.0.20 (`pip install flawfinder`) and
  Cppcheck 2.22.0.
- **Scoring:**
  - A test case is **detected** when a tool warns with the test case's CWE inside a function whose name contains
    `bad`.
  - It is a **false alarm** when the warning falls inside a function whose name contains `good`.
  - Every tool's warnings are placed in functions by the same srcML function spans.

## Python check: `pysuite/`

- **Script and output:** `pysuite_eval.py` writes `pysuite_eval.txt`.
- **Comparison:** against Bandit 1.9.4 (`pip install bandit`, or set `BANDIT`).
- **Cases:** 14 `bad_*` and 15 `good_*` functions, written for the paper.

## Speed

- **Script and output:** `speed.py` writes `speed.txt`.
- **Projects:** set `PROJECTS` to a colon-separated list of folders. The paper's projects and their commits are in
  `speed_projects.txt`.

## Walkthrough and figure

- `example/` holds the four-file service shown in Fig. 2.
- `e2e/tests/index.js` drives a real VS Code end to end:
  `code --extensionDevelopmentPath=../extension --extensionTestsPath=$PWD/e2e/tests example`.
- `shot/` holds the harness that produced Fig. 2, which captures VS Code through its DevTools port
  (`--remote-debugging-port`).

# Evaluation

These are the scripts and outputs behind the numbers in the paper. There are two evaluated versions:
- **`v1-eval`** froze the rules before the first run on CWE-78, 134 and 415. Its outputs are in `v1-eval/`.
- **`v2-eval`** is the version the paper describes. It adds control dependence, control-flow paths, the extended
  srcPtr and the fixes that v1's misses revealed, so its Juliet numbers are not from held-out data. Its outputs are
  in this folder.

`CHANGES.md` lists every change.

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

## Fig. 2: cfingerd 1.4.3 and CVE-2001-0609

- `cve/fetch_cfingerd.sh` downloads cfingerd 1.4.3 and Debian's security fix from snapshot.debian.org, checks
  their SHA-1 hashes, and unpacks `vulnerable/` and `fixed/`. Nothing in them is built or run.
- `cve/cfingerd_tools.txt` holds the output of sliceSec, flawfinder and Cppcheck on both versions.
- `figure/figure.py` takes the screenshot. It drives a real VS Code, with sliceSec installed from its VSIX
  (`cd extension && npx @vscode/vsce package --no-dependencies`), through its remote debugging port with
  Playwright, using keys, the command palette and the mouse. `figure/User/` holds the profile's settings and
  key bindings; set `slicesec.backendPath` to this repository's `slicesec` folder.

## End-to-end test

- `example/` holds a four-file service, and `e2e/tests/index.js` drives a real VS Code end to end on it:
  `code --extensionDevelopmentPath=../extension --extensionTestsPath=$PWD/e2e/tests example`.
- `shot/` holds the harness of an earlier version of Fig. 2.

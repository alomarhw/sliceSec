# Changes

## Since v1-eval (the version evaluated in the paper)
- `break`, `continue` and `goto` after a `free` no longer end the use-after-free and double-free search. Only
  `return`, `throw` and calls that do not return end it. Juliet flow variants 12, 15, 16 and 18 showed the
  mistake.
- Slice queries cache each variable's own lines (tcpdump median 374 ms to 28 ms).
- The server keeps its analysis when a save changes no source file.
- When srcML produces malformed XML, the files are converted one at a time in parallel to find the bad one.
- A call goes to the function of that name in the caller's own file when there is one. Juliet's `static` C helpers
  and its per-test C++ namespaces repeat names across files, so name-only resolution followed calls into other files.
- Control dependence: branches, loop bodies, `switch` cases and the statements after an early exit depend on the
  variables their predicate reads. Forward slices follow it. Taint does not, unless `implicit=True`.
- Pointer analysis with srcPtr (the fork in `srcptr/`, Andersen): pointers in one function that may point to the
  same object alias each other, and the use-after-free check uses the same rule. Hub objects that more than 20
  pointers reach are left out. The hover shows what a pointer points to.
- Writes through a pointer (`n[0] = ..`, `*n = ..`, `n->f = ..`) count as uses of freed memory.
- An output-parameter edge needs the callee to write through the parameter.
- A parameter declared as a pointer, reference or array counts as an output parameter when the callee writes through
  it, whatever srcSlice's folded pointer facts say. In a folder where many files define a function of the same name,
  srcSlice can attach those facts to another file.
- Control-flow paths for each slice, as srcSlice's `controledges` (Alomari et al., JSEP 2014, Sec. 2.5): true and
  false edges from each control statement and next edges between successive slice lines, never between an `if`
  branch and its `else`, and none out of a `return`. Each slice line's enclosing predicates join the slice
  (Sec. 2.4), and lines before the criterion's first definition leave it. The paper's Fig. 2 example is a test.
  Slice results carry `controlEdges`, and the Slice view lists them.
- A write through a pointer must start its statement (`*p = ..`, `p[i] = ..`, `p->f = ..`), so a declaration
  `char *p = q;` is not taken for one.
- Slices follow data dependence (dvars, copies, calls, returns, output parameters, srcSlice pointer copies) and add the
  statements that control dependence reaches, without continuing from them. srcPtr's may-alias pairs drive taint and
  the use-after-free check but not slices. An output parameter needs a write through the parameter itself
  (`*p = ..`, `p[i] = ..`, a copy or input call into p), not a field write (`p->f = ..`). Together these keep
  slices from spreading over most of a program through a shared context struct (tcpdump: median 6 variables).
- Slice queries group lines by function once, and finding the function of a line is a binary search.
- Data written through a pointer (`*p = e`, `*(p++) = e`, `*p++ = e`) now reaches what the pointer points to, and a
  pointer copy in a `for` header (`for (p = buf; ..)`) makes the two alias. srcSlice records neither, so a buffer
  filled one character at a time through a pointer lost its taint. Found on cfingerd 1.4.3 (CVE-2001-0609), whose
  ident reply reaches `syslog` this way; the test `test_copy_through_a_pointer_in_a_loop` covers it. Juliet
  C/C++ 1.3 and the Python suite give the same results as before.

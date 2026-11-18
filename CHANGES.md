# Changes

## Since v1-eval (the version evaluated in the paper)
- `break`, `continue` and `goto` after a `free` no longer end the use-after-free and double-free search. Only
  `return`, `throw` and calls that do not return end it. Juliet flow variants 12, 15, 16 and 18 showed the
  mistake.
- Slice queries cache each variable's own lines (tcpdump median 374 ms to 28 ms).
- The server keeps its analysis when a save changes no source file.
- When srcML produces malformed XML, the files are converted one at a time in parallel to find the bad one.

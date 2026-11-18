# Changes

## Since v1-eval (the version evaluated in the paper)
- `break`, `continue` and `goto` after a `free` no longer end the use-after-free and double-free search. Only
  `return`, `throw` and calls that do not return end it. Juliet flow variants 12, 15, 16 and 18 showed the
  mistake.

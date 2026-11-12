# verify_oep

Scores the candidate offsets printed by `scripts/find_oep.py` before any
dump is attempted. A tail jump can land on a jump table, an import thunk, or
the middle of an instruction on samples with a modified stub; this script
narrows that down to candidates worth disassembling.

Scores:

| score | meaning |
|-------|---------|
| 0 | unmapped or non-executable address |
| 1 | executable, but inside the packer stub itself, or no prologue |
| 2 | executable section plus a prologue-shaped first byte (`push ebp`, `call`, `mov`) |
| 3 | score 2 plus a stack frame setup or an immediate call |

Run it from the Script Manager with the candidates as arguments:

```
verify/verify_oep.py 0x00401234 0x0040a000 0x0040b010
```

Output is one line per candidate:

```
0x0040a000  score 3  plausible OEP  section=.adata
```

Only score 3 candidates should be followed by a dump; score 2 usually means
the stub transferred into a thunk, which still has to be stepped through.
`score 3 alone is not proof` is printed on purpose: verify the first basic
block disassembles cleanly and ends in a branch before trusting it.

# Lean specification

A small core-Lean project (no Mathlib) that states and proves two properties of SentrySearch rules.

- `SentrySearchSpec/IpRule.lean` models the ordered decision in `_classify_ip`
  (`src/core/evidence_admissibility.py`). `publicAddress_sound` proves that a public verdict means no
  candidate network overlaps documentation, special-use or private space and both ends of every
  candidate are globally reachable. `documentation_first` proves that any overlap with documentation
  space decides the verdict.
- `SentrySearchSpec/IpCases.lean` instantiates the model with the production IPv4 ranges and checks a
  table of concrete values by kernel evaluation. `tests/test_formal_ip_cases.py` reads the same table and
  checks each verdict against the production classifier, so the model and the code cannot drift apart
  on these values.
- `SentrySearchSpec/Rubric.lean` proves that the weighted quality score never exceeds the per-section
  bound (5.00), whatever the weights.

Build with the pinned toolchain in `lean-toolchain`:

```bash
cd formal && lake build
```

CI runs the same build in the `Lean specification` job.

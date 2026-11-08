/-!
# IP indicator rule

A model of `_classify_ip` in `src/core/evidence_admissibility.py`. A value yields candidate networks,
each an inclusive address range (a single address is a one-address range). IPv4-mapped and NAT64
values are unwrapped to IPv4 before this point, so the model works on plain ranges.

The decision is ordered and applies to the whole value: no candidate is invalid; then any overlap
with documentation space, then special-use space, then private space; then any candidate whose first
or last address is not globally reachable; otherwise public.
-/

namespace SentrySearchSpec.IpRule

/-- An inclusive address range. -/
structure Net where
  lo : Nat
  hi : Nat
deriving DecidableEq, Repr

/-- Two ranges share at least one address. -/
def overlaps (a b : Net) : Bool := decide (a.lo ≤ b.hi) && decide (b.lo ≤ a.hi)

inductive Verdict where
  | invalid
  | documentation
  | specialUse
  | privateContext
  | nonGlobal
  | public
deriving DecidableEq, Repr

/-- The reserved range lists the rule checks, in precedence order. -/
structure Ranges where
  documentation : List Net
  specialUse : List Net
  privateUse : List Net

/-- Some candidate overlaps some range in `rs`. -/
def touches (cands rs : List Net) : Bool :=
  cands.any fun c => rs.any fun r => overlaps c r

/-- Some candidate has a first or last address that is not globally reachable. -/
def anyNonGlobal (isGlobal : Nat → Bool) (cands : List Net) : Bool :=
  cands.any fun c => !(isGlobal c.lo && isGlobal c.hi)

def classify (rs : Ranges) (isGlobal : Nat → Bool) (cands : List Net) : Verdict :=
  if cands.isEmpty then .invalid
  else if touches cands rs.documentation then .documentation
  else if touches cands rs.specialUse then .specialUse
  else if touches cands rs.privateUse then .privateContext
  else if anyNonGlobal isGlobal cands then .nonGlobal
  else .public

theorem not_touches {cands rs : List Net} (h : touches cands rs = false) :
    ∀ c ∈ cands, ∀ r ∈ rs, overlaps c r = false := by
  intro c hc r hr
  cases hcr : overlaps c r with
  | false => rfl
  | true =>
    have ht : touches cands rs = true := by
      unfold touches
      exact List.any_eq_true.mpr ⟨c, hc, List.any_eq_true.mpr ⟨r, hr, hcr⟩⟩
    rw [h] at ht
    exact absurd ht (by decide)

/-- A public verdict means no candidate overlaps any reserved range and every candidate's first and
last addresses are globally reachable. -/
theorem public_sound {rs : Ranges} {isGlobal : Nat → Bool} {cands : List Net}
    (h : classify rs isGlobal cands = .public) :
    ∀ c ∈ cands,
      (∀ r ∈ rs.documentation ++ rs.specialUse ++ rs.privateUse, overlaps c r = false) ∧
      isGlobal c.lo = true ∧ isGlobal c.hi = true := by
  unfold classify at h
  by_cases h0 : cands.isEmpty = true
  · simp [h0] at h
  by_cases hd : touches cands rs.documentation = true
  · simp [h0, hd] at h
  by_cases hs : touches cands rs.specialUse = true
  · simp [h0, hd, hs] at h
  by_cases hp : touches cands rs.privateUse = true
  · simp [h0, hd, hs, hp] at h
  by_cases hg : anyNonGlobal isGlobal cands = true
  · simp [h0, hd, hs, hp, hg] at h
  simp only [Bool.not_eq_true] at hd hs hp hg
  intro c hc
  refine ⟨?_, ?_⟩
  · intro r hr
    simp only [List.mem_append] at hr
    rcases hr with (hr | hr) | hr
    · exact not_touches hd c hc r hr
    · exact not_touches hs c hc r hr
    · exact not_touches hp c hc r hr
  · have hc' : (!(isGlobal c.lo && isGlobal c.hi)) = false := by
      cases hx : (!(isGlobal c.lo && isGlobal c.hi)) with
      | false => rfl
      | true =>
        have hn : anyNonGlobal isGlobal cands = true := by
          unfold anyNonGlobal
          exact List.any_eq_true.mpr ⟨c, hc, hx⟩
        rw [hg] at hn
        exact absurd hn (by decide)
    revert hc'
    cases isGlobal c.lo <;> cases isGlobal c.hi <;> simp

/-- Documentation space takes precedence: any overlap with it decides the verdict. -/
theorem documentation_first {rs : Ranges} {isGlobal : Nat → Bool} {cands : List Net}
    (h : touches cands rs.documentation = true) :
    classify rs isGlobal cands = .documentation := by
  have hne : cands.isEmpty = false := by
    cases cands with
    | nil => simp [touches] at h
    | cons _ _ => rfl
  simp [classify, hne, h]

end SentrySearchSpec.IpRule

/-!
# Weighted quality score bound

`SectionValidator._calculate_overall_score` takes a weighted mean of section scores (critical
sections weight 1.5, other sections 1.0) and the consistency score (weight 0.5), each bounded to
0–5 by the evaluation models. Here scores are in hundredths (500 = 5.00) and weights in halves
(3, 2, 1), so everything is a natural number.
-/

namespace SentrySearchSpec.Rubric

/-- Pairs of (score, weight). -/
def weightedSum : List (Nat × Nat) → Nat
  | [] => 0
  | (s, w) :: xs => s * w + weightedSum xs

def totalWeight : List (Nat × Nat) → Nat
  | [] => 0
  | (_, w) :: xs => w + totalWeight xs

theorem weightedSum_le (m : Nat) :
    ∀ xs : List (Nat × Nat), (∀ p ∈ xs, p.1 ≤ m) → weightedSum xs ≤ m * totalWeight xs
  | [], _ => by simp [weightedSum, totalWeight]
  | (s, w) :: xs, h => by
    have hs : s ≤ m := h (s, w) (by simp)
    have ih := weightedSum_le m xs fun p hp => h p (by simp [hp])
    have hsw : s * w ≤ m * w := Nat.mul_le_mul_right w hs
    simp only [weightedSum, totalWeight, Nat.mul_add]
    exact Nat.add_le_add hsw ih

/-- The weighted mean of scores bounded by `m` is at most `m` (500 = 5.00 for the rubric). -/
theorem mean_le (m : Nat) (xs : List (Nat × Nat)) (h : ∀ p ∈ xs, p.1 ≤ m) :
    weightedSum xs / totalWeight xs ≤ m := by
  apply Nat.div_le_of_le_mul
  rw [Nat.mul_comm]
  exact weightedSum_le m xs h

end SentrySearchSpec.Rubric

import SentrySearchSpec.IpRule

/-!
# Concrete IPv4 cases

The IPv4 ranges below are the IPv4 entries of the documentation, special-use and private lists in
`src/core/evidence_admissibility.py`. For IPv4, those lists cover every IANA non-global block, so an
address outside all of them is globally reachable; `isGlobal4` encodes exactly that.

Each `entry` line is also read by `tests/test_formal_ip_cases.py`, which checks the same verdicts
against the production classifier. Keep one entry per line.
-/

namespace SentrySearchSpec.IpCases
open SentrySearchSpec.IpRule

def ip (a b c d : Nat) : Nat := ((a * 256 + b) * 256 + c) * 256 + d

/-- The block of `len` leading bits containing `a.b.c.d` (host bits cleared). -/
def cidr (a b c d len : Nat) : Net :=
  let size := 2 ^ (32 - len)
  let base := ip a b c d / size * size
  ⟨base, base + size - 1⟩

def host (a b c d : Nat) : Net := cidr a b c d 32

def ipv4 : Ranges where
  documentation := [cidr 192 0 2 0 24, cidr 198 51 100 0 24, cidr 203 0 113 0 24]
  specialUse := [cidr 0 0 0 0 8, cidr 100 64 0 0 10, cidr 127 0 0 0 8, cidr 169 254 0 0 16,
    cidr 192 0 0 0 24, cidr 192 88 99 0 24, cidr 198 18 0 0 15, cidr 224 0 0 0 4, cidr 240 0 0 0 4]
  privateUse := [cidr 10 0 0 0 8, cidr 172 16 0 0 12, cidr 192 168 0 0 16]

def isGlobal4 (a : Nat) : Bool :=
  !((ipv4.documentation ++ ipv4.specialUse ++ ipv4.privateUse).any fun r => decide (r.lo ≤ a ∧ a ≤ r.hi))

structure Case where
  value : String
  cands : List Net
  expected : Verdict

def entry (value : String) (n : Net) (expected : Verdict) : Case := ⟨value, [n], expected⟩

def entries : List Case := [
  entry "8.8.8.8" (host 8 8 8 8) .publicAddress,
  entry "1.1.1.0/24" (cidr 1 1 1 0 24) .publicAddress,
  entry "203.0.113.7" (host 203 0 113 7) .documentation,
  entry "203.0.112.0/23" (cidr 203 0 112 0 23) .documentation,
  entry "198.0.0.0/7" (cidr 198 0 0 0 7) .documentation,
  entry "0.0.0.0/0" (cidr 0 0 0 0 0) .documentation,
  entry "96.0.0.0/3" (cidr 96 0 0 0 3) .specialUse,
  entry "192.0.0.9" (host 192 0 0 9) .specialUse,
  entry "100.64.0.1" (host 100 64 0 1) .specialUse,
  entry "8.0.0.0/5" (cidr 8 0 0 0 5) .privateContext,
  entry "10.20.30.40" (host 10 20 30 40) .privateContext,
  entry "172.15.255.255" (host 172 15 255 255) .publicAddress
]

theorem entries_hold :
    entries.all (fun c => classify ipv4 isGlobal4 c.cands == c.expected) = true := by
  decide +kernel

end SentrySearchSpec.IpCases

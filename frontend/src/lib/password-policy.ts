const passwordSymbols = "!@#$%^&*()_+-=[]{};'\\:\"|<>?,./`~"

export const passwordPolicySummary =
  "Use at least 12 characters with a lowercase letter, uppercase letter, number, and symbol."

export function meetsPasswordPolicy(password: string) {
  return (
    password.length >= 12 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    [...password].some((character) => passwordSymbols.includes(character))
  )
}

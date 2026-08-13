"use client"

import { useState } from "react"
import Link from "next/link"
import { useAuth } from "@/contexts/AuthContext"
import { AuthFrame, AuthNotice } from "@/components/auth/AuthFrame"
import { TurnstileWidget } from "@/components/auth/TurnstileWidget"

const fieldClass =
  "mt-2 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-sm text-zinc-950 outline-none transition-colors placeholder:text-zinc-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"

export default function ForgotPassword() {
  const [email, setEmail] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [captchaToken, setCaptchaToken] = useState<string | null>(null)
  const [captchaResetKey, setCaptchaResetKey] = useState(0)
  const { requestPasswordReset } = useAuth()

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError("")

    if (!captchaToken) {
      setError("Complete the security check before requesting a recovery link.")
      return
    }

    setLoading(true)

    try {
      const { error } = await requestPasswordReset(email, captchaToken)

      if (error) {
        setError(error.message)
      } else {
        setSuccess(true)
      }
    } catch {
      setError("Something went wrong. Try again.")
    } finally {
      setLoading(false)
      setCaptchaToken(null)
      setCaptchaResetKey((current) => current + 1)
    }
  }

  if (success) {
    return (
      <AuthNotice
        title="Check your email"
        description="If an account exists for that email, we sent a password recovery link. Open it in this browser to choose a new password."
        actionHref="/auth/signin"
        actionLabel="Return to sign in"
        notice="Use the newest recovery link if you request more than one."
      />
    )
  }

  return (
    <AuthFrame
      eyebrow="Account recovery"
      title="Reset your password"
      description="Enter the email you used for SentrySearch. We will send a secure recovery link if an account exists."
      footer={
        <Link
          href="/auth/signin"
          className="font-medium text-blue-700 underline-offset-4 hover:underline"
        >
          Return to sign in
        </Link>
      }
    >
      <form className="space-y-5" onSubmit={handleSubmit}>
        {error && (
          <div
            role="alert"
            className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm leading-6 text-red-800"
          >
            {error}
          </div>
        )}

        <div>
          <label htmlFor="email" className="block text-sm font-medium text-zinc-800">
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            className={fieldClass}
            placeholder="you@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </div>

        <TurnstileWidget
          action="password_reset"
          onTokenChange={setCaptchaToken}
          resetKey={captchaResetKey}
        />

        <button
          type="submit"
          disabled={loading || !captchaToken}
          className="flex h-11 w-full items-center justify-center rounded-lg bg-zinc-950 px-4 text-sm font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-60"
        >
          {loading ? "Sending recovery link…" : "Send recovery link"}
        </button>
      </form>
    </AuthFrame>
  )
}

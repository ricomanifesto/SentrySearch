"use client"

import { useState } from "react"
import Link from "next/link"
import { useAuth } from "@/contexts/AuthContext"
import { AuthFrame, AuthNotice } from "@/components/auth/AuthFrame"

const fieldClass =
  "mt-2 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-sm text-zinc-950 outline-none transition-colors placeholder:text-zinc-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"

export default function ResetPassword() {
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const { user, loading: authLoading, updatePassword } = useAuth()

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError("")

    if (password !== confirmPassword) {
      setError("Those passwords don't match.")
      return
    }

    if (password.length < 6) {
      setError("Use a password of at least 6 characters.")
      return
    }

    setLoading(true)

    try {
      const { error } = await updatePassword(password)

      if (error) {
        setError(error.message)
      } else {
        setSuccess(true)
      }
    } catch {
      setError("Something went wrong. Try again.")
    } finally {
      setLoading(false)
    }
  }

  if (authLoading) {
    return (
      <AuthFrame
        eyebrow="Account recovery"
        title="Checking your recovery link"
        description="Confirming the secure session before accepting a new password."
        footer={<span>Keep this page open while the link is verified.</span>}
      >
        <div role="status" className="text-sm leading-6 text-zinc-600">
          Checking recovery access…
        </div>
      </AuthFrame>
    )
  }

  if (!user) {
    return (
      <AuthNotice
        title="Recovery link unavailable"
        description="This recovery link is invalid or expired. Request a new link and open it in the same browser."
        actionHref="/auth/forgot-password"
        actionLabel="Request a new link"
        notice="Request a new recovery link to restart the secure reset flow."
      />
    )
  }

  if (success) {
    return (
      <AuthNotice
        title="Password updated"
        description="Your new password is active. You can continue into your SentrySearch workspace."
        actionHref="/dashboard"
        actionLabel="Open your workspace"
        notice="Your password was changed for this account."
      />
    )
  }

  return (
    <AuthFrame
      eyebrow="Account recovery"
      title="Choose a new password"
      description="Use at least 6 characters. Your new password will replace the previous one for this account."
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
          <label htmlFor="password" className="block text-sm font-medium text-zinc-800">
            New password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            className={fieldClass}
            placeholder="Use at least 6 characters"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        <div>
          <label
            htmlFor="confirmPassword"
            className="block text-sm font-medium text-zinc-800"
          >
            Confirm new password
          </label>
          <input
            id="confirmPassword"
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            required
            className={fieldClass}
            placeholder="Repeat the password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="flex h-11 w-full items-center justify-center rounded-lg bg-zinc-950 px-4 text-sm font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-60"
        >
          {loading ? "Updating password…" : "Update password"}
        </button>
      </form>
    </AuthFrame>
  )
}

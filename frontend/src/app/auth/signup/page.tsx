"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { useAuth } from "@/contexts/AuthContext"
import { AuthFrame, AuthNotice } from "@/components/auth/AuthFrame"

export default function SignUp() {
  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const { signUp, user } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (user) {
      router.push("/")
    }
  }, [user, router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setSuccess(false)

    if (password !== confirmPassword) {
      setError("Passwords do not match")
      return
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters long")
      return
    }

    setLoading(true)

    try {
      const { error } = await signUp(email, password, name)

      if (error) {
        setError(error.message)
      } else {
        setSuccess(true)
      }
    } catch {
      setError("An unexpected error occurred. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <AuthNotice
        title="Confirm your workspace email"
        description="We sent a confirmation link to your inbox. Complete that step to activate report generation, saved intelligence, and source review."
        actionHref="/auth/signin"
        actionLabel="Return to analyst access"
      />
    )
  }

  return (
    <AuthFrame
      eyebrow="Workspace request"
      title="Create an analyst workspace"
      description="Set up access for report generation, saved intelligence, and source-backed review queues."
      footer={
        <p>
          Already have access?{" "}
          <Link
            href="/auth/signin"
            className="font-medium text-[#4d5f24] underline-offset-4 hover:underline"
          >
            Open your workspace
          </Link>
        </p>
      }
    >
      <form className="space-y-5" onSubmit={handleSubmit}>
        {error && (
          <div
            role="alert"
            className="border border-[#efc7c3] bg-[#fff7f6] px-4 py-3 text-sm leading-6 text-[#9d2b22]"
          >
            {error}
          </div>
        )}

        <div>
          <label
            htmlFor="name"
            className="block text-sm font-medium text-[#343832]"
          >
            Analyst name
          </label>
          <input
            id="name"
            name="name"
            type="text"
            autoComplete="name"
            required
            className="mt-2 block h-11 w-full border border-[#cfd2c6] bg-white px-3 text-sm text-[#171915] outline-none placeholder:text-[#898f82] focus:border-[#6f7b41] focus:ring-2 focus:ring-[#dfe7c7]"
            placeholder="Threat intelligence analyst"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        <div>
          <label
            htmlFor="email"
            className="block text-sm font-medium text-[#343832]"
          >
            Work email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            className="mt-2 block h-11 w-full border border-[#cfd2c6] bg-white px-3 text-sm text-[#171915] outline-none placeholder:text-[#898f82] focus:border-[#6f7b41] focus:ring-2 focus:ring-[#dfe7c7]"
            placeholder="analyst@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div>
          <label
            htmlFor="password"
            className="block text-sm font-medium text-[#343832]"
          >
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            required
            className="mt-2 block h-11 w-full border border-[#cfd2c6] bg-white px-3 text-sm text-[#171915] outline-none placeholder:text-[#898f82] focus:border-[#6f7b41] focus:ring-2 focus:ring-[#dfe7c7]"
            placeholder="Use at least 6 characters"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <div>
          <label
            htmlFor="confirmPassword"
            className="block text-sm font-medium text-[#343832]"
          >
            Confirm password
          </label>
          <input
            id="confirmPassword"
            name="confirmPassword"
            type="password"
            required
            className="mt-2 block h-11 w-full border border-[#cfd2c6] bg-white px-3 text-sm text-[#171915] outline-none placeholder:text-[#898f82] focus:border-[#6f7b41] focus:ring-2 focus:ring-[#dfe7c7]"
            placeholder="Repeat the workspace password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="flex h-11 w-full items-center justify-center bg-[#20231f] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#343832] focus:outline-none focus:ring-2 focus:ring-[#6f7b41] focus:ring-offset-2 disabled:pointer-events-none disabled:opacity-60"
        >
          {loading ? "Creating workspace..." : "Create workspace"}
        </button>
      </form>
    </AuthFrame>
  )
}

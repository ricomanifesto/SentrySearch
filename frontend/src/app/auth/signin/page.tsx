"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { useAuth } from "@/contexts/AuthContext"
import { AuthFrame } from "@/components/auth/AuthFrame"

export default function SignIn() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const { signIn, user } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (user) {
      router.push("/")
    }
  }, [user, router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const { error } = await signIn(email, password)

      if (error) {
        setError(error.message)
      } else {
        router.push("/")
      }
    } catch {
      setError("An unexpected error occurred. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthFrame
      eyebrow="Analyst access"
      title="Open your intelligence workspace"
      description="Continue reviewing saved reports, source context, and generated threat intelligence from one account."
      footer={
        <p>
          New to SentrySearch?{" "}
          <Link
            href="/auth/signup"
            className="font-medium text-[#4d5f24] underline-offset-4 hover:underline"
          >
            Request a workspace account
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
            autoComplete="current-password"
            required
            className="mt-2 block h-11 w-full border border-[#cfd2c6] bg-white px-3 text-sm text-[#171915] outline-none placeholder:text-[#898f82] focus:border-[#6f7b41] focus:ring-2 focus:ring-[#dfe7c7]"
            placeholder="Enter your workspace password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="flex h-11 w-full items-center justify-center bg-[#20231f] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#343832] focus:outline-none focus:ring-2 focus:ring-[#6f7b41] focus:ring-offset-2 disabled:pointer-events-none disabled:opacity-60"
        >
          {loading ? "Opening workspace..." : "Open workspace"}
        </button>
      </form>
    </AuthFrame>
  )
}

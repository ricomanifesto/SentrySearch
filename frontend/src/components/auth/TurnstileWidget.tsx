"use client"

import Script from "next/script"
import { useCallback, useEffect, useRef } from "react"

type TurnstileOptions = {
  sitekey: string
  action: string
  theme: "light" | "dark" | "auto"
  language: "en-US"
  size: "normal" | "compact" | "flexible"
  callback: (token: string) => void
  "expired-callback": () => void
  "error-callback": () => void
}

type TurnstileApi = {
  render: (container: HTMLElement, options: TurnstileOptions) => string
  reset: (widgetId: string) => void
  remove: (widgetId: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

type TurnstileWidgetProps = {
  action: "signin" | "signup" | "password_reset"
  onTokenChange: (token: string | null) => void
  resetKey: number
}

export function TurnstileWidget({
  action,
  onTokenChange,
  resetKey,
}: TurnstileWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const widgetIdRef = useRef<string | null>(null)
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY

  const renderWidget = useCallback(() => {
    if (!siteKey || !containerRef.current || !window.turnstile || widgetIdRef.current) {
      return
    }

    widgetIdRef.current = window.turnstile.render(containerRef.current, {
      sitekey: siteKey,
      action,
      theme: "auto",
      language: "en-US",
      size: "flexible",
      callback: (token) => onTokenChange(token),
      "expired-callback": () => onTokenChange(null),
      "error-callback": () => onTokenChange(null),
    })
  }, [action, onTokenChange, siteKey])

  useEffect(() => {
    renderWidget()

    return () => {
      if (widgetIdRef.current && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current)
        widgetIdRef.current = null
      }
    }
  }, [renderWidget])

  useEffect(() => {
    if (resetKey === 0 || !widgetIdRef.current || !window.turnstile) {
      return
    }

    onTokenChange(null)
    window.turnstile.reset(widgetIdRef.current)
  }, [onTokenChange, resetKey])

  if (!siteKey) {
    return (
      <p role="alert" className="text-sm leading-6 text-red-700">
        The security check is unavailable. Try again later.
      </p>
    )
  }

  return (
    <div aria-label="Security check" className="space-y-2">
      <Script
        id="cloudflare-turnstile"
        src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        strategy="afterInteractive"
        onReady={renderWidget}
      />
      <div ref={containerRef} className="min-h-16 w-full" />
      <p className="text-xs leading-5 text-zinc-500">
        Protected by Cloudflare Turnstile.
      </p>
    </div>
  )
}

"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/AuthContext"
import { createClient } from "@/lib/supabase"
import { EyeIcon, EyeSlashIcon, KeyIcon } from "@heroicons/react/24/outline"

export default function Settings() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [apiKey, setApiKey] = useState("")
  const [showApiKey, setShowApiKey] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState("")
  const supabase = createClient()

  // Redirect if not authenticated
  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/auth/signin")
    }
  }, [user, authLoading, router])

  // Load user profile
  useEffect(() => {
    if (user) {
      loadUserProfile()
    }
  }, [user]) // loadUserProfile is stable and doesn't need to be in deps

  const loadUserProfile = async () => {
    if (!user) return
    
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('user_profiles')
        .select('anthropic_api_key_encrypted')
        .eq('id', user.id)
        .single()

      if (error && error.code !== 'PGRST116') { // PGRST116 = no rows returned
        console.error('Error loading profile:', error)
      } else if (data) {
        // Decrypt API key (simplified - in production use proper encryption)
        setApiKey(data.anthropic_api_key_encrypted || "")
      }
    } catch (err) {
      console.error("Failed to load profile:", err)
    } finally {
      setLoading(false)
    }
  }

  const saveApiKey = async () => {
    if (!user) return
    
    setSaving(true)
    setMessage("")
    
    try {
      // Validate API key format
      if (apiKey && !apiKey.startsWith('sk-ant-')) {
        setMessage("Error: Invalid Anthropic API key format")
        return
      }

      // Upsert user profile
      const { error } = await supabase
        .from('user_profiles')
        .upsert({
          id: user.id,
          anthropic_api_key_encrypted: apiKey || null,
        })

      if (error) {
        setMessage(`Error: ${error.message}`)
      } else {
        setMessage("API key saved successfully")
      }
    } catch {
      setMessage("Failed to save API key")
    } finally {
      setSaving(false)
    }
  }

  if (authLoading || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  const userMetadata = user.user_metadata || {}

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
            <p className="mt-1 text-sm text-gray-600">
              Manage your account settings and API configuration
            </p>
          </div>

          <div className="px-6 py-6 space-y-8">
            {/* Account Information */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 mb-4">Account Information</h2>
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Name</label>
                    <div className="mt-1 text-sm text-gray-900">
                      {userMetadata.name || 'Not provided'}
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Email</label>
                    <div className="mt-1 text-sm text-gray-900">{user.email}</div>
                  </div>
                </div>
              </div>
            </div>

            {/* API Key Configuration */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 mb-4">API Configuration</h2>
              <div className="space-y-4">
                <div>
                  <label htmlFor="apiKey" className="block text-sm font-medium text-gray-700">
                    Anthropic API Key
                  </label>
                  <p className="text-sm text-gray-500 mb-2">
                    Your Anthropic API key is required to generate threat intelligence reports.
                    Get your key from{" "}
                    <a
                      href="https://console.anthropic.com/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:text-blue-800"
                    >
                      Anthropic Console
                    </a>
                  </p>
                  <div className="relative">
                    <input
                      id="apiKey"
                      name="apiKey"
                      type={showApiKey ? "text" : "password"}
                      className="block w-full px-3 py-2 pr-12 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      placeholder="sk-ant-api03-..."
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowApiKey(!showApiKey)}
                    >
                      {showApiKey ? (
                        <EyeSlashIcon className="h-5 w-5 text-gray-400" />
                      ) : (
                        <EyeIcon className="h-5 w-5 text-gray-400" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={saveApiKey}
                    disabled={saving}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <KeyIcon className="h-4 w-4 mr-2" />
                    {saving ? "Saving..." : "Save API Key"}
                  </button>

                  {message && (
                    <div
                      className={`text-sm ${
                        message.includes("Error")
                          ? "text-red-600"
                          : "text-green-600"
                      }`}
                    >
                      {message}
                    </div>
                  )}
                </div>

                {/* API Key Security Notice */}
                <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <KeyIcon className="h-5 w-5 text-blue-400" />
                    </div>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-blue-800">
                        API Key Security
                      </h3>
                      <div className="mt-2 text-sm text-blue-700">
                        <ul className="list-disc list-inside space-y-1">
                          <li>Your API key is stored securely in Supabase</li>
                          <li>Only you can access your API key</li>
                          <li>Keys are used only for generating your reports</li>
                          <li>You can update or remove your key anytime</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
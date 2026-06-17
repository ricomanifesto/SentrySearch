"use client"

import { useAuth } from "@/contexts/AuthContext"
import { AuthGuard } from "@/components/AuthGuard"

export default function Settings() {
  const { user } = useAuth()
  const userMetadata = user?.user_metadata || {}

  return (
    <AuthGuard>
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
              <p className="mt-1 text-sm text-gray-600">
                Manage account details and report-generation preferences.
              </p>
            </div>

            <div className="px-6 py-6 space-y-8">
              <div>
                <h2 className="text-lg font-medium text-gray-900 mb-4">
                  Account Information
                </h2>
                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">
                        Name
                      </label>
                      <div className="mt-1 text-sm text-gray-900">
                        {userMetadata.name || "Not provided"}
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">
                        Email
                      </label>
                      <div className="mt-1 text-sm text-gray-900">{user?.email}</div>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h2 className="text-lg font-medium text-gray-900 mb-4">
                  Report Generation
                </h2>
                <div className="bg-gray-50 rounded-lg p-4 text-sm text-gray-700">
                  Report generation uses the configured server-side model gateway.
                  No user-level provider key is required here.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AuthGuard>
  )
}

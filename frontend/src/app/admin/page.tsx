'use client';

import React from 'react';

export default function AdminPage() {
  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Admin Dashboard
          </h1>
          <p className="text-lg text-gray-600 mb-8">
            Administrative features coming soon.
          </p>
          <div className="bg-white rounded-lg shadow p-6">
            <p className="text-gray-500">
              User management, system monitoring, and configuration settings will be available in a future update.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
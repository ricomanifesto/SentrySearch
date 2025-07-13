/**
 * Admin Panel
 * 
 * Administrative interface for user management, system configuration,
 * and platform oversight.
 */

'use client';

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  UsersIcon,
  CogIcon,
  ServerIcon,
  ExclamationTriangleIcon,
  TrashIcon,
  PencilIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';

interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  status: 'active' | 'inactive' | 'suspended';
  last_login: string;
  created_at: string;
  reports_count: number;
  api_usage_count: number;
}

interface SystemStatus {
  api_health: 'healthy' | 'degraded' | 'down';
  database_health: 'healthy' | 'degraded' | 'down';
  storage_health: 'healthy' | 'degraded' | 'down';
  active_users: number;
  total_requests_24h: number;
  error_rate_24h: number;
  avg_response_time_ms: number;
}

const roleOptions = [
  { value: 'admin', label: 'Administrator' },
  { value: 'analyst', label: 'Threat Analyst' },
  { value: 'viewer', label: 'Viewer' },
];

const statusOptions = [
  { value: 'active', label: 'Active' },
  { value: 'inactive', label: 'Inactive' },
  { value: 'suspended', label: 'Suspended' },
];

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<'users' | 'system' | 'settings'>('users');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isEditingUser, setIsEditingUser] = useState(false);
  const queryClient = useQueryClient();

  // Fetch users
  const { data: users, isLoading: usersLoading } = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: () => api.getUsers(),
  });

  // Fetch system status
  const { data: systemStatus, isLoading: systemLoading } = useQuery({
    queryKey: ['admin', 'system'],
    queryFn: () => api.getSystemStatus(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // User management mutations
  const updateUserMutation = useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: Partial<User> }) => 
      api.updateUser(userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      setIsEditingUser(false);
      setSelectedUser(null);
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) => api.deleteUser(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      setSelectedUser(null);
    },
  });

  const handleEditUser = (user: User) => {
    setSelectedUser(user);
    setIsEditingUser(true);
  };

  const handleDeleteUser = (user: User) => {
    if (confirm(`Are you sure you want to delete user ${user.username}? This action cannot be undone.`)) {
      deleteUserMutation.mutate(user.id);
    }
  };

  const getRoleVariant = (role: string) => {
    switch (role) {
      case 'admin': return 'error';
      case 'analyst': return 'info';
      case 'viewer': return 'default';
      default: return 'default';
    }
  };

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'inactive': return 'warning';
      case 'suspended': return 'error';
      default: return 'default';
    }
  };

  const getHealthVariant = (health: string) => {
    switch (health) {
      case 'healthy': return 'success';
      case 'degraded': return 'warning';
      case 'down': return 'error';
      default: return 'default';
    }
  };

  const tabs = [
    { id: 'users', name: 'User Management', icon: UsersIcon },
    { id: 'system', name: 'System Status', icon: ServerIcon },
    { id: 'settings', name: 'Settings', icon: CogIcon },
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center space-x-2 mb-2">
          <ShieldCheckIcon className="h-8 w-8 text-red-600" />
          <h1 className="text-3xl font-bold text-gray-900">Admin Panel</h1>
        </div>
        <p className="text-gray-600">
          Manage users, monitor system health, and configure platform settings
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 mb-8">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  isActive
                    ? 'border-red-500 text-red-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-5 w-5" />
                <span>{tab.name}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Users Tab */}
      {activeTab === 'users' && (
        <div className="space-y-6">
          {/* Users Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <Card>
              <CardContent className="py-6">
                <div className="flex items-center">
                  <UsersIcon className="h-8 w-8 text-blue-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Total Users</p>
                    <p className="text-2xl font-bold text-gray-900">{users?.length || 0}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="flex items-center">
                  <CheckCircleIcon className="h-8 w-8 text-green-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Active Users</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {users?.filter(u => u.status === 'active').length || 0}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="flex items-center">
                  <ClockIcon className="h-8 w-8 text-orange-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Recent Logins</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {users?.filter(u => {
                        const lastLogin = new Date(u.last_login);
                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        return lastLogin > yesterday;
                      }).length || 0}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="flex items-center">
                  <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Suspended</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {users?.filter(u => u.status === 'suspended').length || 0}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Users Table */}
          <Card>
            <CardHeader>
              <CardTitle>User Management</CardTitle>
            </CardHeader>
            <CardContent>
              {usersLoading ? (
                <div className="animate-pulse space-y-4">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="h-16 bg-gray-200 rounded"></div>
                  ))}
                </div>
              ) : users?.length === 0 ? (
                <div className="text-center py-8">
                  <UsersIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-500">No users found</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          User
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Role
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Status
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Activity
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Last Login
                        </th>
                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {users?.map((user) => (
                        <tr key={user.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <div className="h-10 w-10 flex-shrink-0">
                                <div className="h-10 w-10 rounded-full bg-gray-300 flex items-center justify-center">
                                  <span className="text-sm font-medium text-gray-700">
                                    {user.username.charAt(0).toUpperCase()}
                                  </span>
                                </div>
                              </div>
                              <div className="ml-4">
                                <div className="text-sm font-medium text-gray-900">{user.username}</div>
                                <div className="text-sm text-gray-500">{user.email}</div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <Badge variant={getRoleVariant(user.role)} size="sm">
                              {user.role}
                            </Badge>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <Badge variant={getStatusVariant(user.status)} size="sm">
                              {user.status}
                            </Badge>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <div>
                              <div>{user.reports_count} reports</div>
                              <div className="text-xs text-gray-500">{user.api_usage_count} API calls</div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {formatRelativeTime(user.last_login)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <div className="flex justify-end space-x-2">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleEditUser(user)}
                              >
                                <PencilIcon className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="danger"
                                size="sm"
                                onClick={() => handleDeleteUser(user)}
                              >
                                <TrashIcon className="h-4 w-4" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* System Tab */}
      {activeTab === 'system' && (
        <div className="space-y-6">
          {/* System Health Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card>
              <CardContent className="py-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-500">API Health</p>
                    <Badge variant={getHealthVariant(systemStatus?.api_health || 'down')} size="lg">
                      {systemStatus?.api_health || 'Unknown'}
                    </Badge>
                  </div>
                  <ServerIcon className="h-8 w-8 text-blue-600" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-500">Database</p>
                    <Badge variant={getHealthVariant(systemStatus?.database_health || 'down')} size="lg">
                      {systemStatus?.database_health || 'Unknown'}
                    </Badge>
                  </div>
                  <ServerIcon className="h-8 w-8 text-green-600" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-500">Storage</p>
                    <Badge variant={getHealthVariant(systemStatus?.storage_health || 'down')} size="lg">
                      {systemStatus?.storage_health || 'Unknown'}
                    </Badge>
                  </div>
                  <ServerIcon className="h-8 w-8 text-orange-600" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* System Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card>
              <CardContent className="py-6">
                <div className="text-center">
                  <p className="text-2xl font-bold text-gray-900">
                    {systemStatus?.active_users || 0}
                  </p>
                  <p className="text-sm text-gray-500">Active Users</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="text-center">
                  <p className="text-2xl font-bold text-gray-900">
                    {systemStatus?.total_requests_24h || 0}
                  </p>
                  <p className="text-sm text-gray-500">Requests (24h)</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="text-center">
                  <p className="text-2xl font-bold text-gray-900">
                    {systemStatus?.error_rate_24h?.toFixed(2) || '0.00'}%
                  </p>
                  <p className="text-sm text-gray-500">Error Rate (24h)</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-6">
                <div className="text-center">
                  <p className="text-2xl font-bold text-gray-900">
                    {systemStatus?.avg_response_time_ms || 0}ms
                  </p>
                  <p className="text-sm text-gray-500">Avg Response Time</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* System Actions */}
          <Card>
            <CardHeader>
              <CardTitle>System Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Button variant="outline" className="justify-start">
                  <ServerIcon className="h-4 w-4 mr-2" />
                  Restart API Server
                </Button>
                <Button variant="outline" className="justify-start">
                  <ServerIcon className="h-4 w-4 mr-2" />
                  Clear Cache
                </Button>
                <Button variant="outline" className="justify-start">
                  <ServerIcon className="h-4 w-4 mr-2" />
                  Export Logs
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Settings Tab */}
      {activeTab === 'settings' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Platform Configuration</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Input
                    label="API Rate Limit (requests/hour)"
                    type="number"
                    defaultValue="1000"
                  />
                  <Input
                    label="Max Report Size (MB)"
                    type="number"
                    defaultValue="10"
                  />
                  <Input
                    label="Session Timeout (minutes)"
                    type="number"
                    defaultValue="60"
                  />
                  <Select
                    label="Default User Role"
                    options={roleOptions}
                    defaultValue="viewer"
                  />
                </div>
                
                <div className="pt-4">
                  <Button>Save Configuration</Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Security Settings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">Force HTTPS</h4>
                    <p className="text-sm text-gray-500">Redirect all HTTP traffic to HTTPS</p>
                  </div>
                  <input type="checkbox" defaultChecked className="h-4 w-4 text-blue-600" />
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">Two-Factor Authentication</h4>
                    <p className="text-sm text-gray-500">Require 2FA for admin accounts</p>
                  </div>
                  <input type="checkbox" defaultChecked className="h-4 w-4 text-blue-600" />
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">API Key Rotation</h4>
                    <p className="text-sm text-gray-500">Automatically rotate API keys every 90 days</p>
                  </div>
                  <input type="checkbox" className="h-4 w-4 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
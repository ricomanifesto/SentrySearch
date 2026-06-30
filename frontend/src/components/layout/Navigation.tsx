/**
 * Main navigation component for SentrySearch
 */

'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import {
  MagnifyingGlassIcon,
  DocumentTextIcon,
  ChartBarIcon,
  PlusIcon,
  Bars3Icon,
  XMarkIcon,
  ShieldCheckIcon,
  ArrowDownTrayIcon,
  UserIcon,
  ArrowRightOnRectangleIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/ThemeToggle';

const navigation = [
  { name: 'Briefing', href: '/dashboard', icon: ChartBarIcon },
  { name: 'Reports', href: '/reports', icon: DocumentTextIcon },
  { name: 'Analytics', href: '/analytics', icon: ChartBarIcon },
  { name: 'Export', href: '/export', icon: ArrowDownTrayIcon },
  { name: 'Generate', href: '/generate', icon: PlusIcon },
];

const adminNavigation = [
  { name: 'Admin', href: '/admin', icon: ShieldCheckIcon },
];

export function Navigation() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const pathname = usePathname();
  const { user, signOut } = useAuth();

  // App navigation is only meaningful once signed in.
  const allNavigation = user ? [...navigation, ...adminNavigation] : [];
  const homeHref = user ? '/dashboard' : '/';

  return (
    <nav className="border-b border-zinc-200 bg-white">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 justify-between">
          {/* Logo and main navigation */}
          <div className="flex">
            {/* Logo */}
            <div className="flex flex-shrink-0 items-center">
              <Link href={homeHref} className="flex items-center space-x-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">
                  <MagnifyingGlassIcon className="h-5 w-5 text-white" />
                </div>
                <span className="text-lg font-semibold tracking-tight text-zinc-950">
                  SentrySearch
                </span>
              </Link>
            </div>

            {/* Desktop navigation */}
            <div className="hidden sm:ml-8 sm:flex sm:space-x-6">
              {allNavigation.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;

                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={cn(
                      'inline-flex items-center space-x-1.5 border-b-2 px-1 pt-1 text-sm font-medium transition-colors',
                      isActive
                        ? 'border-blue-600 text-zinc-950'
                        : 'border-transparent text-zinc-500 hover:border-zinc-300 hover:text-zinc-800'
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.name}</span>
                  </Link>
                );
              })}
            </div>
          </div>

          {/* Mobile menu button */}
          <div className="flex items-center gap-1 sm:hidden">
            <ThemeToggle />
            <button
              type="button"
              className="inline-flex items-center justify-center rounded-md p-2 text-zinc-500 hover:bg-zinc-100 hover:text-zinc-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              <span className="sr-only">Open main menu</span>
              {mobileMenuOpen ? (
                <XMarkIcon className="block h-6 w-6" />
              ) : (
                <Bars3Icon className="block h-6 w-6" />
              )}
            </button>
          </div>

          {/* Desktop right side */}
          <div className="hidden sm:flex sm:items-center sm:space-x-4">
            <ThemeToggle />
            {user ? (
              <>
                <Link
                  href="/settings"
                  className="rounded-md p-2 text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-700"
                  title="Settings"
                >
                  <Cog6ToothIcon className="h-5 w-5" />
                </Link>
                <div className="flex items-center space-x-3">
                  <div className="flex items-center space-x-2">
                    <UserIcon className="h-5 w-5 text-zinc-400" />
                    <span className="text-sm text-zinc-700">
                      {user.user_metadata?.name || user.email}
                    </span>
                  </div>
                  <button
                    onClick={() => signOut()}
                    className="rounded-md p-2 text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-700"
                    title="Sign out"
                  >
                    <ArrowRightOnRectangleIcon className="h-5 w-5" />
                  </button>
                </div>
              </>
            ) : (
              <div className="flex items-center space-x-2">
                <Link
                  href="/auth/signin"
                  className="rounded-lg px-3 py-2 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-100"
                >
                  Sign in
                </Link>
                <Link
                  href="/auth/signup"
                  className="rounded-lg bg-zinc-950 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800"
                >
                  Sign up
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="border-t border-zinc-200 sm:hidden">
          <div className="space-y-1 pb-3 pt-2">
            {allNavigation.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;

              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    'flex items-center space-x-3 border-l-4 py-2 pl-3 pr-4 text-base font-medium transition-colors',
                    isActive
                      ? 'border-blue-600 bg-blue-50 text-blue-700'
                      : 'border-transparent text-zinc-500 hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-700'
                  )}
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <Icon className="h-5 w-5" />
                  <span>{item.name}</span>
                </Link>
              );
            })}

            {!user && (
              <div className="flex flex-col gap-2 px-3 pt-2">
                <Link
                  href="/auth/signin"
                  className="flex h-11 items-center justify-center rounded-lg border border-zinc-300 text-sm font-medium text-zinc-800"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Sign in
                </Link>
                <Link
                  href="/auth/signup"
                  className="flex h-11 items-center justify-center rounded-lg bg-zinc-950 text-sm font-medium text-white"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Sign up
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </nav>
  );
}

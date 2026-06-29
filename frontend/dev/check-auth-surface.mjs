import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const signInPath = resolve(here, '../src/app/auth/signin/page.tsx');
const signUpPath = resolve(here, '../src/app/auth/signup/page.tsx');
const authFramePath = resolve(here, '../src/components/auth/AuthFrame.tsx');
const authGuardPath = resolve(here, '../src/components/AuthGuard.tsx');
const globalsPath = resolve(here, '../src/app/globals.css');

const signIn = await readFile(signInPath, 'utf8');
const signUp = await readFile(signUpPath, 'utf8');
const authFrame = await readFile(authFramePath, 'utf8');
const authGuard = await readFile(authGuardPath, 'utf8');
const globals = await readFile(globalsPath, 'utf8');
const combined = `${signIn}\n${signUp}\n${authFrame}\n${authGuard}`;

const expectations = [
  {
    name: 'uses a shared auth frame for the unauthenticated boundary',
    source: authFrame,
    pattern: /export function AuthFrame/,
  },
  {
    name: 'frames auth as a threat-intelligence workspace entry',
    source: authFrame,
    pattern: /Source-backed threat intelligence/,
  },
  {
    name: 'keeps product-specific source review context visible',
    source: authFrame,
    pattern: /source context/,
  },
  {
    name: 'uses product-specific sign-in title copy',
    source: signIn,
    pattern: /Open your workspace/,
  },
  {
    name: 'uses product-specific sign-up title copy',
    source: signUp,
    pattern: /Create your workspace/,
  },
  {
    name: 'uses product-specific success copy',
    source: signUp,
    pattern: /Confirm your email/,
  },
  {
    name: 'keeps sign-in routed through the auth API boundary',
    source: signIn,
    pattern: /signIn\(email, password\)/,
  },
  {
    name: 'keeps sign-up routed through the auth API boundary',
    source: signUp,
    pattern: /signUp\(email, password, name\)/,
  },
  {
    name: 'keeps accessible error alert semantics',
    source: combined,
    pattern: /role="alert"/,
  },
  {
    name: 'uses product-specific protected-route boundary copy',
    source: authGuard,
    pattern: /Sign in to review saved intelligence/,
  },
  {
    name: 'uses accessible workspace access loading semantics',
    source: authGuard,
    pattern: /role="status"[\s\S]*aria-label="Checking workspace access"/,
  },
  {
    name: 'keeps required form controls',
    source: combined,
    pattern: /required/,
  },
  {
    name: 'removes generic placeholder identities',
    source: combined,
    absentPattern: /John Doe|john@example\.com/,
  },
  {
    name: 'removes old generic auth headings',
    source: combined,
    absentPattern: /Sign in to SentrySearch|Create your account|Authentication Required/,
  },
  {
    name: 'does not link to an unimplemented password reset route',
    source: combined,
    absentPattern: /forgot-password/,
  },
  {
    name: 'does not rely on the old stock gray auth background',
    source: combined,
    absentPattern: /bg-gray-50/,
  },
  {
    name: 'uses stable tokenized panel framing',
    source: authFrame,
    pattern: /rounded-2xl border border-zinc-200 bg-white p-6/,
  },
  {
    name: 'declares the auth entry surface contract',
    source: authFrame,
    pattern: /data-surface="auth-entry"/,
  },
  {
    name: 'uses a stable trust-signal hook for responsive visual QA',
    source: authFrame,
    pattern: /data-testid="auth-trust-signals"/,
  },
  {
    name: 'keeps mobile auth hero type below desktop scale',
    source: authFrame,
    pattern: /text-4xl[\s\S]*sm:text-5xl/,
  },
  {
    name: 'uses a compact mobile auth layout before expanding on desktop',
    source: authFrame,
    pattern: /gap-10[\s\S]*lg:gap-16/,
  },
  {
    name: 'surfaces the auth form earlier on mobile',
    source: authFrame,
    pattern: /lg:min-h-\[calc\(100vh-8rem\)\]/,
  },
  {
    name: 'keeps light auth surfaces out of global dark-mode inversion',
    source: globals,
    absentPattern: /prefers-color-scheme:\s*dark/,
  },
];

const failures = expectations.filter(({ source, pattern, absentPattern }) => {
  if (pattern && !pattern.test(source)) {
    return true;
  }

  if (absentPattern && absentPattern.test(source)) {
    return true;
  }

  return false;
});

if (failures.length > 0) {
  console.error('Auth surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Auth surface contract check passed (${expectations.length} expectations).`);

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const signInPath = resolve(here, '../src/app/auth/signin/page.tsx');
const signUpPath = resolve(here, '../src/app/auth/signup/page.tsx');
const authFramePath = resolve(here, '../src/components/auth/AuthFrame.tsx');

const signIn = await readFile(signInPath, 'utf8');
const signUp = await readFile(signUpPath, 'utf8');
const authFrame = await readFile(authFramePath, 'utf8');
const combined = `${signIn}\n${signUp}\n${authFrame}`;

const expectations = [
  {
    name: 'uses a shared auth frame for the unauthenticated boundary',
    source: authFrame,
    pattern: /export function AuthFrame/,
  },
  {
    name: 'frames auth as a threat-intelligence workspace entry',
    source: authFrame,
    pattern: /Enter the intelligence review room/,
  },
  {
    name: 'keeps product-specific source review context visible',
    source: authFrame,
    pattern: /source context/,
  },
  {
    name: 'uses product-specific sign-in title copy',
    source: signIn,
    pattern: /Open your intelligence workspace/,
  },
  {
    name: 'uses product-specific sign-up title copy',
    source: signUp,
    pattern: /Create an analyst workspace/,
  },
  {
    name: 'uses product-specific success copy',
    source: signUp,
    pattern: /Confirm your workspace email/,
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
    absentPattern: /Sign in to SentrySearch|Create your account/,
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
    name: 'uses stable non-rounded panel framing',
    source: authFrame,
    pattern: /border border-\[#d8d9ce\] bg-white p-6/,
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


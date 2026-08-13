import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const signInPath = resolve(here, '../src/app/auth/signin/page.tsx');
const signUpPath = resolve(here, '../src/app/auth/signup/page.tsx');
const forgotPasswordPath = resolve(here, '../src/app/auth/forgot-password/page.tsx');
const resetPasswordPath = resolve(here, '../src/app/auth/reset-password/page.tsx');
const authFramePath = resolve(here, '../src/components/auth/AuthFrame.tsx');
const authGuardPath = resolve(here, '../src/components/AuthGuard.tsx');
const authContextPath = resolve(here, '../src/contexts/AuthContext.tsx');
const turnstilePath = resolve(here, '../src/components/auth/TurnstileWidget.tsx');
const passwordPolicyPath = resolve(here, '../src/lib/password-policy.ts');
const settingsPath = resolve(here, '../src/app/settings/page.tsx');
const globalsPath = resolve(here, '../src/app/globals.css');

const signIn = await readFile(signInPath, 'utf8');
const signUp = await readFile(signUpPath, 'utf8');
const forgotPassword = await readFile(forgotPasswordPath, 'utf8');
const resetPassword = await readFile(resetPasswordPath, 'utf8');
const authFrame = await readFile(authFramePath, 'utf8');
const authGuard = await readFile(authGuardPath, 'utf8');
const authContext = await readFile(authContextPath, 'utf8');
const turnstile = await readFile(turnstilePath, 'utf8');
const passwordPolicy = await readFile(passwordPolicyPath, 'utf8');
const settings = await readFile(settingsPath, 'utf8');
const globals = await readFile(globalsPath, 'utf8');
const combined = `${signIn}\n${signUp}\n${forgotPassword}\n${resetPassword}\n${authFrame}\n${authGuard}\n${settings}\n${turnstile}\n${passwordPolicy}`;

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
    name: 'uses recovery-specific email guidance',
    source: forgotPassword,
    pattern: /notice="Use the newest recovery link/,
  },
  {
    name: 'uses recovery-specific expired-link guidance',
    source: resetPassword,
    pattern: /notice="Request a new recovery link/,
  },
  {
    name: 'uses recovery-specific password-update guidance',
    source: resetPassword,
    pattern: /notice="Your password was changed/,
  },
  {
    name: 'keeps sign-in routed through the auth API boundary',
    source: signIn,
    pattern: /signIn\(email, password, captchaToken\)/,
  },
  {
    name: 'keeps sign-up routed through the auth API boundary',
    source: signUp,
    pattern: /signUp\(email, password, name, captchaToken\)/,
  },
  {
    name: 'returns signup confirmations to the current app',
    source: authContext,
    pattern: /emailRedirectTo: `\$\{window\.location\.origin\}\/auth\/signin`/,
  },
  {
    name: 'offers password recovery from sign-in',
    source: signIn,
    pattern: /href="\/auth\/forgot-password"[\s\S]*Forgot password\?/,
  },
  {
    name: 'requests recovery through the auth API boundary',
    source: forgotPassword,
    pattern: /requestPasswordReset\(email, captchaToken\)/,
  },
  {
    name: 'updates recovered passwords through the auth API boundary',
    source: resetPassword,
    pattern: /updatePassword\(password\)/,
  },
  {
    name: 'uses the supported Supabase recovery request',
    source: authContext,
    pattern: /resetPasswordForEmail\(email,[\s\S]*\/auth\/reset-password/,
  },
  {
    name: 'requires a server-verified CAPTCHA token for public auth calls',
    source: authContext,
    pattern: /signUp[\s\S]*captchaToken[\s\S]*signInWithPassword[\s\S]*captchaToken[\s\S]*resetPasswordForEmail[\s\S]*captchaToken/,
  },
  {
    name: 'renders Cloudflare Turnstile through the canonical script',
    source: turnstile,
    pattern: /https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js\?render=explicit/,
  },
  {
    name: 'fails closed when the public Turnstile key is unavailable',
    source: turnstile,
    pattern: /if \(!siteKey\)[\s\S]*security check is unavailable/,
  },
  {
    name: 'protects sign-in, sign-up, and password recovery forms',
    source: `${signIn}\n${signUp}\n${forgotPassword}`,
    pattern: /action="signin"[\s\S]*action="signup"[\s\S]*action="password_reset"/,
  },
  {
    name: 'matches the production password policy',
    source: passwordPolicy,
    pattern: /password\.length >= 12[\s\S]*\/\[a-z\]\/[\s\S]*\/\[A-Z\]\/[\s\S]*\/\[0-9\]\//,
  },
  {
    name: 'uses the supported Supabase password update',
    source: authContext,
    pattern: /updateUser\(\{ password \}\)/,
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
    name: 'accepts regular email addresses in account copy',
    source: combined,
    absentPattern: /Work email|analyst@company\.com/,
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

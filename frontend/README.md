# SentrySearch Frontend

This directory contains the SentrySearch web app. Public pages explain the product and show a sample report. Signed-in pages provide report generation, review, search, export, analytics, and account settings.

## Run It

You need Node.js 20.9 or newer and a SentrySearch API running on `http://localhost:8001`.

```bash
npm ci
cp .env.example .env.local
npm run dev
```

Open `http://localhost:3000`.

Set these values in `.env.local`:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8001
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
NEXT_PUBLIC_TURNSTILE_SITE_KEY=your_public_turnstile_site_key
```

Supabase provides sign-in and session handling. Cloudflare Turnstile protects account creation. All browser calls to protected API routes include the current Supabase access token.

## Main Routes

- `/` and `/sample`: public product overview and sample report.
- `/auth/*`: sign-up, sign-in, password reset, and recovery.
- `/generate`: create a threat profile.
- `/reports` and `/reports/[id]`: search, filter, inspect, retry evaluation, and delete saved reports.
- `/export`: prepare accepted report evidence packages with judgment history.
- `/analytics`: review volume, content quality, unresolved work, threat mix, activity, and authoring-route performance.
- `/settings`: view workspace identity, access posture, and generation policy.

## Checks

```bash
npm run check:surface-coverage
npm run test:experience
npm run lint
npm run build
```

`check:surface-coverage` verifies that each product route keeps its required content and controls. `test:experience` covers authentication transitions, error messages, report rendering, and shared workspace behavior.

## Stack

- Next.js 16 with the App Router
- React 19 and TypeScript
- Tailwind CSS 4
- TanStack Query for server state
- Axios for API requests
- Supabase for browser authentication

## Vercel

Deploy this directory as the Vercel project root and add the four public environment variables shown above. Set `NEXT_PUBLIC_API_URL` to the deployed FastAPI origin, such as `https://your-api-domain.com`, instead of the local value. Production builds run `npm run build` and write the Next.js output to `.next`.

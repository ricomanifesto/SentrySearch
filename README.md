# SentrySearch

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-lockup-dark.png">
    <img src="docs/assets/logo-lockup-light.png" alt="SentrySearch" width="341">
  </picture>
</div>

SentrySearch researches a malware family, attack tool, or exposed technology and saves the result as a source-backed threat profile.

**[Open SentrySearch](https://sentry-search.vercel.app)**

## What You Can Do

- Generate a report with threat context, detection guidance, mitigations, and source evidence.
- Search saved reports by target, category, threat type, date, tags, review state, and quality score.
- Re-run a failed quality evaluation without repeating the research step.
- Review report volume, quality, threat distribution, and model-route performance.
- Export selected reports as evidence packages.

Reports and analytics are private to the signed-in workspace.

## How Generation Works

The default generator is `google/gemma-4-26b-a4b-it:free`; the default evaluator is `google/gemma-4-31b-it:free`. SentrySearch calls both through OpenRouter's Chat Completions API and pins routing to Google AI Studio. If a free route is unavailable, it retries the paid route for the same model.

The generator can use OpenRouter's hosted web search. Its output must contain the required threat-profile fields defined with Pydantic before it is saved. Each report records the model requested by the app, the route selected for the request, and the model reported by the provider. The report page shows when a fallback route was used.

## Run It Locally

You need Python 3.11, [`uv`](https://docs.astral.sh/uv/), Node.js 20.9 or newer, npm, PostgreSQL, and Supabase project credentials.

Start the FastAPI backend:

```bash
uv sync --locked
cp .env.example .env
uv run python run_api.py
```

Start the Next.js frontend in a second terminal:

```bash
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

The API listens on `http://localhost:8001`; the frontend listens on `http://localhost:3000`. Keep `NEXT_PUBLIC_API_URL=http://localhost:8001` in both environment files.

The example files list every required variable. OpenRouter is needed for live generation, Supabase for authentication, PostgreSQL for report metadata and search, and S3 for report files and exports.

## Validation Without Live Services

```bash
uv sync --locked
uv run python dev/check_local_setup.py
```

This checks the environment contract, Python formatting, linting, types, tests, FastAPI imports, API documentation, health endpoints, and authentication boundaries. It does not call OpenRouter, Supabase, AWS, Railway, Vercel, Cloudflare, or a local PostgreSQL server.

Run the frontend checks after installing its locked dependencies:

```bash
cd frontend
npm run check:surface-coverage
npm run test:experience
npm run lint
npm run build
```

## Architecture

- **Web app:** Next.js 16, React 19, TypeScript, and Tailwind CSS on Vercel.
- **API:** FastAPI, SQLAlchemy, and Pydantic on Railway.
- **Authentication:** Supabase verifies users and scopes every report query to its workspace.
- **Storage:** PostgreSQL holds report metadata, search fields, source records, and lifecycle state. S3 holds Markdown reports and trace files.
- **Model access:** A small OpenRouter client handles generation, web search, evaluation, retry rules, error mapping, and route records.

The legacy experimental retrieval modules have been removed. Search in the current product means authenticated search over saved PostgreSQL report records.

## Related Projects

- [SentryDigest](https://github.com/ricomanifesto/SentryDigest) collects and archives security news.
- [SentryInsight](https://github.com/ricomanifesto/SentryInsight) publishes exploitation-focused reports from that news.

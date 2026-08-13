# SentrySearch

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-lockup-dark.png">
    <img src="docs/assets/logo-lockup-light.png" alt="SentrySearch" width="341">
  </picture>
</div>

SentrySearch turns scattered threat research into searchable security profiles for malware, attack tools, and targeted technologies, with persistent reports, hybrid search, and detection guidance in one workspace.

**Live app:** [sentry-search.vercel.app](https://sentry-search.vercel.app)

## What It Does

SentrySearch generates structured threat intelligence profiles from a user-supplied topic, then stores and indexes those reports for later retrieval. It is built for cases where the research target is specific: a malware family, attack tool, targeted technology, or threat-relevant keyword.

## Core Capabilities

- **Threat analysis:** generates technical profiles with threat landscape context and detection guidance.
- **Hybrid search:** combines vector similarity search with keyword retrieval across threat intelligence data.
- **Report management:** stores generated reports with filtering, search, quality scores, and processing metadata.
- **User isolation:** supports authenticated, multi-tenant report access with admin controls.

## Usage

Visit [sentry-search.vercel.app](https://sentry-search.vercel.app), create an account, and generate a threat intelligence report for any malware, attack tool, or technology. Report generation routes `meta-llama/llama-3.3-70b-instruct` through OpenRouter's native Chat Completions API with hosted web search and strict Pydantic validation.

## Local Setup

Backend dependencies are managed with `uv` from `pyproject.toml` and `uv.lock`. Frontend dependencies are installed from `frontend/package-lock.json`.

```bash
# Backend
uv sync --locked
cp .env.example .env
uv run python run_api.py

# Frontend, in a second terminal
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

The local FastAPI server defaults to `http://localhost:8001`. The frontend uses `NEXT_PUBLIC_API_URL=http://localhost:8001` in local development.

## Local Validation

Run the local setup gate before touching live services:

```bash
uv sync --locked
uv run python dev/check_local_setup.py
```

This verifies the local environment, documentation and frontend URL contract, backend linting and formatting, type checks, pytest, FastAPI imports, API docs rendering, health endpoint behavior, protected report creation without Supabase credentials, and the Cloudflare Worker request contract. It does not call OpenRouter, Supabase, AWS, Pinecone, Railway, Vercel, Cloudflare, or local PostgreSQL.

Frontend validation requires `frontend/node_modules`:

```bash
cd frontend
npm run lint
npm run build
```

## Architecture

- **Frontend:** Next.js, TypeScript, Tailwind CSS, deployed on Vercel.
- **Backend:** FastAPI, SQLAlchemy, Pydantic, deployed on Railway.
- **Auth:** Supabase JWT authentication.
- **Data:** PostgreSQL stores report metadata and search indexes; S3 stores markdown reports and artifacts.
- **Search:** Pinecone provides vector similarity search; Cloudflare Workers orchestrate hybrid search.
- **AI:** A direct OpenRouter Chat Completions client executes the configured model and bounded hosted web search, maps typed provider errors, and validates strict Pydantic structured output.

## Related Projects

- [SentryDigest](https://github.com/ricomanifesto/SentryDigest) - security feed aggregation and briefing output
- [SentryInsight](https://github.com/ricomanifesto/SentryInsight) - exploitation-focused threat reporting

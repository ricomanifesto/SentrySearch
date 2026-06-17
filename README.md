
# SentrySearch

<div align="center">
  <img src="docs/assets/logo.png" alt="SentrySearch Logo" width="400" />
</div>

AI-powered threat intelligence platform that generates detailed security profiles for malware, attack tools, and targeted technologies using advanced language models and hybrid search.

## Usage

Visit the web application: **https://sentry-search.vercel.app**

Create an account, add your Anthropic Claude API key, and generate threat intelligence reports for any malware, attack tool, or technology.

## Local Setup

Backend dependencies are managed with `uv` from `pyproject.toml` and `uv.lock`.
Frontend dependencies are installed from `frontend/package-lock.json`.

```bash
# Backend
uv sync --locked
cp .env.example .env
uv run python run_api.py

# Frontend, in a second terminal
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

The local FastAPI server defaults to `http://localhost:8001`. The frontend uses
`NEXT_PUBLIC_API_URL=http://localhost:8001` in local development.

## Local Validation

Run the local setup gate before touching live services:

```bash
uv sync --locked
uv run python dev/check_local_setup.py
```

This verifies the local env/docs/frontend URL contract, runs backend ruff checks,
black formatting checks, ty type checks, pytest, the FastAPI app import, API docs
rendering, the health endpoint's degraded local shape, and that report creation
remains protected without Supabase credentials. It does not call Anthropic,
Supabase, AWS, Pinecone, Railway, Vercel, Cloudflare, or a local PostgreSQL
service.

Frontend validation requires `frontend/node_modules`:

```bash
cd frontend
npm run lint
npm run build
```

## Core Features

**Threat Analysis**: Claude analyzes web research and generates comprehensive profiles with technical details, threat landscape assessment, and detection guidance.

**Hybrid Search**: Vector similarity search through Pinecone combined with traditional keyword search across threat intelligence databases.

**Report Management**: Persistent storage with filtering, search, and analytics. Reports include quality scores and processing metadata.

**User System**: Multi-tenant architecture with user isolation, JWT authentication, and admin access controls.

## Architecture

**Frontend**: Next.js application deployed on Vercel with user authentication via Supabase.

**Backend**: FastAPI server on Railway providing RESTful API endpoints for report generation and management.

**Data Layer**: PostgreSQL (AWS RDS) stores report metadata and search indexes. S3 stores markdown reports and artifacts. Pinecone provides vector similarity search.

**AI & Search**: Anthropic Claude generates threat analysis. Cloudflare Workers orchestrate hybrid search combining vector and keyword matching across distributed edge locations.

## Technology Stack

**Frontend**: Next.js, TypeScript, Tailwind CSS

**Backend**: FastAPI, SQLAlchemy, Pydantic

**Database**: PostgreSQL, S3, Pinecone

**AI**: Anthropic Claude, vector embeddings

**Infrastructure**: Railway, Vercel, AWS RDS/S3, Cloudflare Workers

**Auth**: Supabase JWT authentication

## Related Projects

- [SentryDigest](https://github.com/ricomanifesto/SentryDigest) - Cybersecurity news aggregator
- [SentryInsight](https://github.com/ricomanifesto/SentryInsight) - AI-powered threat analysis

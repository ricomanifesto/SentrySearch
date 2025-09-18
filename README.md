
# SentrySearch

<div align="center">
  <img src="docs/assets/logo.png" alt="SentrySearch Logo" width="400" />
</div>

AI-powered threat intelligence platform that generates detailed security profiles for malware, attack tools, and targeted technologies using advanced language models and hybrid search.

## Usage

Visit the web application: **https://sentry-search.vercel.app**

Create an account, add your Anthropic Claude API key, and generate threat intelligence reports for any malware, attack tool, or technology.

## Architecture

**Frontend**: Next.js application deployed on Vercel with user authentication via Supabase.

**Backend**: FastAPI server on Railway providing RESTful API endpoints for report generation and management.

**Data Layer**: PostgreSQL (AWS RDS) stores report metadata and search indexes. S3 stores markdown reports and artifacts. Pinecone provides vector similarity search.

**AI & Search**: Anthropic Claude generates threat analysis. Cloudflare Workers orchestrate hybrid search combining vector and keyword matching across distributed edge locations.

## Core Features

**Threat Analysis**: Claude analyzes web research and generates comprehensive profiles with technical details, threat landscape assessment, and detection guidance.

**Hybrid Search**: Vector similarity search through Pinecone combined with traditional keyword search across threat intelligence databases.

**Report Management**: Persistent storage with filtering, search, and analytics. Reports include quality scores and processing metadata.

**User System**: Multi-tenant architecture with user isolation, JWT authentication, and admin access controls.

## Usage

Visit the web application: **https://sentry-search.vercel.app**

Create an account, add your Anthropic Claude API key, and generate threat intelligence reports for any malware, attack tool, or technology.

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
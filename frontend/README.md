# SentrySearch Frontend

Professional Next.js frontend for SentrySearch threat intelligence platform.

## Features

- Modern, responsive UI with Tailwind CSS
- Server-side rendering with Next.js 14
- Real-time search and filtering
- Analytics dashboard
- Optimistic updates with React Query
- Mobile-responsive design

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- SentrySearch API server running on `http://localhost:8000`

### Installation

```bash
# Install dependencies
npm install

# Copy environment config
cp .env.example .env.local

# Start development server
npm run dev
```

The application will be available at `http://localhost:3000`.

### Configuration

Update `.env.local` with your API server URL:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Technology Stack

- **Framework**: Next.js 14 with App Router
- **Styling**: Tailwind CSS
- **State Management**: React Query (TanStack Query)
- **HTTP Client**: Axios
- **Icons**: Heroicons
- **Typography**: Inter font
- **Deployment**: Vercel (optimized)

## Development

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run start        # Start production server
npm run lint         # Run ESLint
```

## API Integration

The frontend connects to the SentrySearch FastAPI backend through a typed API client. Make sure the API server is running before starting the frontend.

## Deployment on Vercel

1. Connect your GitHub repository to Vercel
2. Set environment variables in Vercel dashboard:
   ```
   NEXT_PUBLIC_API_URL=https://your-api-domain.com
   ```
3. Deploy automatically on push to main branch

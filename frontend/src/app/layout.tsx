import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Providers } from "@/lib/providers";
import { Navigation } from "@/components/layout/Navigation";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://sentry-search.vercel.app"),
  title: "SentrySearch | Threat Intelligence Research Workspace",
  description: "SentrySearch turns scattered threat research into searchable security profiles for malware, attack tools, and targeted technologies, with persistent reports, hybrid search, and detection guidance in one workspace.",
  keywords: ["threat intelligence", "cybersecurity", "AI", "malware analysis", "security research"],
  authors: [{ name: "Michael Rico", url: "https://ricomanifesto.com/" }],
  creator: "Michael Rico",
  publisher: "Rico Manifesto",
  alternates: {
    canonical: "https://sentry-search.vercel.app/",
  },
  robots: {
    index: true,
    follow: true,
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://sentry-search.vercel.app/",
    title: "SentrySearch | Threat Intelligence Research Workspace",
    description: "SentrySearch turns scattered threat research into searchable security profiles, persistent reports, hybrid search, and detection guidance.",
    siteName: "SentrySearch",
  },
  twitter: {
    card: "summary_large_image",
    title: "SentrySearch | Threat Intelligence Research Workspace",
    description: "SentrySearch turns scattered threat research into searchable security profiles, persistent reports, hybrid search, and detection guidance.",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: "SentrySearch",
  url: "https://sentry-search.vercel.app/",
  description:
    "SentrySearch turns scattered threat research into searchable security profiles for malware, attack tools, and targeted technologies, with persistent reports, hybrid search, and detection guidance in one workspace.",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  author: {
    "@type": "Person",
    name: "Michael Rico",
    url: "https://ricomanifesto.com/",
  },
  publisher: {
    "@type": "Organization",
    name: "Rico Manifesto",
    url: "https://ricomanifesto.com/",
  },
  codeRepository: "https://github.com/ricomanifesto/SentrySearch",
};

const themeScript = `(function(){try{var t=localStorage.getItem('theme');var d=t?t==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;if(d)document.documentElement.classList.add('dark');}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify(structuredData).replace(/</g, "\\u003c"),
          }}
        />
      </head>
      <body className={`${inter.variable} font-sans antialiased h-full bg-[var(--surface-0)]`}>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <Providers>
          <div className="min-h-full">
            <Navigation />
            <main className="pb-8">
              {children}
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}

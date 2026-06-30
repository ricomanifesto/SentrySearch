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
  title: "SentrySearch - AI-Powered Threat Intelligence",
  description: "Professional threat intelligence platform powered by AI for cybersecurity analysis and research.",
  keywords: ["threat intelligence", "cybersecurity", "AI", "malware analysis", "security research"],
  authors: [{ name: "SentrySearch Team" }],
  creator: "SentrySearch",
  publisher: "SentrySearch",
  robots: {
    index: true,
    follow: true,
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://sentrysearch.vercel.app",
    title: "SentrySearch - AI-Powered Threat Intelligence",
    description: "Professional threat intelligence platform powered by AI",
    siteName: "SentrySearch",
  },
  twitter: {
    card: "summary_large_image",
    title: "SentrySearch - AI-Powered Threat Intelligence",
    description: "Professional threat intelligence platform powered by AI",
  },
};

const themeScript = `(function(){try{var t=localStorage.getItem('theme');var d=t?t==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;if(d)document.documentElement.classList.add('dark');}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
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

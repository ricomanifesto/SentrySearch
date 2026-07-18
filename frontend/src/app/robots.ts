import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: ["/", "/sample"],
      disallow: [
        "/admin",
        "/analytics",
        "/api",
        "/auth",
        "/dashboard",
        "/export",
        "/generate",
        "/reports",
        "/search",
        "/settings",
      ],
    },
    sitemap: "https://sentry-search.vercel.app/sitemap.xml",
    host: "https://sentry-search.vercel.app",
  };
}

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
    sitemap: "https://sentrysearch.ricomanifesto.com/sitemap.xml",
    host: "https://sentrysearch.ricomanifesto.com",
  };
}

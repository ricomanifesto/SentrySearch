import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://sentry-search.vercel.app/",
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: "https://sentry-search.vercel.app/sample",
      changeFrequency: "monthly",
      priority: 0.8,
    },
  ];
}

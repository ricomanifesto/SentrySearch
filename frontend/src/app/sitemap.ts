import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://sentrysearch.ricomanifesto.com/",
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: "https://sentrysearch.ricomanifesto.com/sample",
      changeFrequency: "monthly",
      priority: 0.8,
    },
  ];
}

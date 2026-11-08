type CitableSource = { source_id?: string | null; url: string };

const SOURCE_CITATION = /\[(S[1-9]\d*)\]\(#source-\1\)/g;

function httpUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

/**
 * Rewrite in-page source citations for a file that leaves the report page.
 *
 * The narrative links `[S1](#source-S1)` to the page's source rail, which does
 * not exist in a downloaded file. Each citation instead links to that source's
 * own URL, or stays as plain `[S1]` text when no safe URL is known.
 */
export function portableCitations(markdown: string, sources: CitableSource[] | undefined): string {
  const urls = new Map<string, string>();
  for (const source of sources ?? []) {
    const url = source.source_id ? httpUrl(source.url) : null;
    if (source.source_id && url && !urls.has(source.source_id)) urls.set(source.source_id, url);
  }
  return markdown.replace(SOURCE_CITATION, (_match, sourceId: string) => {
    const url = urls.get(sourceId);
    return url ? `[${sourceId}](<${url}>)` : `[${sourceId}]`;
  });
}

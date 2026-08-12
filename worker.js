/**
 * Cloudflare Workers - SentrySearch Hybrid Search
 * 
 * Implements hybrid vector + keyword search using Pinecone and Cloudflare KV
 * for production-ready ML threat intelligence retrieval.
 */

const MAX_QUERY_COUNT = 10;
const MAX_QUERY_LENGTH = 500;
const MAX_RESULTS = 50;

/**
 * Main request handler
 */
export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};

async function handleRequest(request, env) {
  if (request.method === 'OPTIONS') {
    return withCors(new Response(null, { status: 204 }));
  }

  try {
    const path = new URL(request.url).pathname;
    let response;
    switch (path) {
      case '/hybrid-search':
        response = await handleHybridSearch(request, env);
        break;
      case '/vector-search':
        response = await handleVectorSearch(request, env);
        break;
      case '/keyword-search':
        response = await handleKeywordSearch(request, env);
        break;
      case '/metadata/companies':
        response = await handleMetadata(request, env, 'meta:companies', 'companies');
        break;
      case '/metadata/years':
        response = await handleMetadata(request, env, 'meta:years', 'years');
        break;
      case '/metadata/techniques':
        response = await handleMetadata(request, env, 'meta:techniques', 'techniques');
        break;
      case '/health': {
        const keywordReady = Boolean(env.SENTRY_KV);
        const vectorReady = Boolean(
          env.PINECONE_API_KEY &&
          env.PINECONE_INDEX_HOST &&
          env.EMBEDDING_API_KEY &&
          env.EMBEDDING_API_URL
        );
        response = jsonResponse(
          {
            status: keywordReady ? (vectorReady ? 'healthy' : 'degraded') : 'unready',
            keyword_search: keywordReady ? 'configured' : 'unavailable',
            vector_search: vectorReady ? 'configured' : 'unavailable',
            timestamp: new Date().toISOString()
          },
          keywordReady ? 200 : 503
        );
        break;
      }
      default:
        response = jsonResponse({ error: 'NOT_FOUND' }, 404);
    }
    return withCors(response);
  } catch (error) {
    console.error('Request handling error:', error);
    return withCors(jsonResponse({ error: 'INTERNAL_SERVER_ERROR' }, 500));
  }
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function withCors(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(getCorsHeaders())) {
    headers.set(name, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function normalizeQuery(value) {
  if (typeof value !== 'string') return null;
  const query = value.trim();
  return query.length > 0 && query.length <= MAX_QUERY_LENGTH ? query : null;
}

function normalizeMaxResults(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 10;
  return Math.min(MAX_RESULTS, Math.max(1, Math.trunc(parsed)));
}

function normalizeFilters(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const normalizeList = (candidate) => Array.isArray(candidate)
    ? candidate.filter((item) => typeof item === 'string').slice(0, 20)
    : [];
  return {
    companies: normalizeList(value.companies),
    years: normalizeList(value.years),
    techniques: normalizeList(value.techniques)
  };
}

function normalizeHybridWeights(value) {
  const vector = Number(value?.vector);
  const keyword = Number(value?.keyword);
  if (!Number.isFinite(vector) || !Number.isFinite(keyword) || vector < 0 || keyword < 0) {
    return { vector: 0.6, keyword: 0.4 };
  }
  const total = vector + keyword;
  return total > 0
    ? { vector: vector / total, keyword: keyword / total }
    : { vector: 0.6, keyword: 0.4 };
}

/**
 * Hybrid Search Handler - Combines vector and keyword search
 */
async function handleHybridSearch(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'METHOD_NOT_ALLOWED' }, 405);
  }

  const startTime = Date.now();
  try {
    const body = await request.json();
    const queries = Array.isArray(body.queries)
      ? body.queries
          .slice(0, MAX_QUERY_COUNT)
          .map(normalizeQuery)
          .filter(Boolean)
      : [];
    if (queries.length === 0) {
      return jsonResponse(
        { error: 'INVALID_REQUEST', message: 'At least one valid query is required' },
        400
      );
    }

    const maxResults = normalizeMaxResults(body.maxResults);
    const hybridWeights = normalizeHybridWeights(body.hybridWeights);
    const filters = normalizeFilters(body.filters);
    const requireBothMethods = body.requireBothMethods === true;

    // Perform parallel searches
    const searchPromises = queries.map(query => performHybridSearchForQuery(query, maxResults, filters, env));
    const searchResults = await Promise.all(searchPromises);

    // Combine and deduplicate results
    const combinedResults = await combineSearchResults(
      searchResults,
      hybridWeights,
      requireBothMethods,
      maxResults,
      env
    );

    // Sort by hybrid score and limit results
    const finalResults = combinedResults
      .sort((a, b) => b.scores.hybridScore - a.scores.hybridScore)
      .slice(0, maxResults);

    const processingTime = Date.now() - startTime;

    const response = {
      results: finalResults,
      metadata: {
        totalResults: finalResults.length,
        vectorResults: combinedResults.filter(r => r.retrievalMethod === 'vector' || r.retrievalMethod === 'hybrid').length,
        keywordResults: combinedResults.filter(r => r.retrievalMethod === 'keyword' || r.retrievalMethod === 'hybrid').length,
        hybridResults: combinedResults.filter(r => r.retrievalMethod === 'hybrid').length,
        processingTimeMs: processingTime,
        queriesProcessed: queries
      }
    };

    return jsonResponse(response);
  } catch (error) {
    console.error('Hybrid search error:', error);
    return jsonResponse({ error: 'SEARCH_FAILED' }, 500);
  }
}

/**
 * Perform hybrid search for a single query
 */
async function performHybridSearchForQuery(query, maxResults, filters, env) {
  // Perform vector and keyword searches in parallel
  const [vectorResults, keywordResults] = await Promise.all([
    performVectorSearch(query, maxResults, filters, env),
    performKeywordSearch(query, maxResults, filters, env)
  ]);

  return {
    query,
    vectorResults,
    keywordResults
  };
}

/**
 * Vector Search using Pinecone
 */
async function performVectorSearch(query, maxResults, filters, env) {
  try {
    if (!env.PINECONE_INDEX_HOST || !env.PINECONE_API_KEY) {
      console.warn('Vector search is unavailable because Pinecone is not configured');
      return [];
    }

    const queryEmbedding = await generateQueryEmbedding(query, env);
    if (!queryEmbedding) {
      return [];
    }

    // Prepare Pinecone query
    const pineconeQuery = {
      vector: queryEmbedding,
      topK: maxResults,
      includeMetadata: true,
      includeValues: false
    };

    // Add filters if provided
    if (filters && Object.keys(filters).length > 0) {
      const pineconeFilter = buildPineconeFilter(filters);
      if (pineconeFilter) pineconeQuery.filter = pineconeFilter;
    }

    // Query Pinecone
    const response = await fetch(`${env.PINECONE_INDEX_HOST}/query`, {
      method: 'POST',
      headers: {
        'Api-Key': env.PINECONE_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(pineconeQuery)
    });

    if (!response.ok) {
      console.error('Pinecone query failed with status %s', response.status);
      return [];
    }

    const data = await response.json();
    return data.matches?.map(match => ({
      chunkId: match.id,
      score: match.score,
      metadata: match.metadata,
      method: 'vector'
    })) || [];
  } catch (error) {
    console.error('Vector search error:', error);
    return [];
  }
}

/**
 * Keyword Search using Cloudflare KV and BM25
 */
async function performKeywordSearch(query, maxResults, filters, env) {
  try {
    const queryTerms = tokenizeQuery(query);
    if (queryTerms.length === 0) return [];

    const termPromises = queryTerms.map(term => getBM25ScoresForTerm(term, env));
    const termResults = await Promise.all(termPromises);
    const documentScores = new Map();

    for (let i = 0; i < queryTerms.length; i++) {
      const termData = termResults[i];
      if (termData && termData.postingsList) {
        for (const posting of termData.postingsList) {
          const chunkId = posting.chunkId || posting.chunk_id;
          const score = Number(posting.score);
          if (!chunkId || !Number.isFinite(score)) continue;
          documentScores.set(chunkId, (documentScores.get(chunkId) || 0) + score);
        }
      }
    }

    const candidates = Array.from(documentScores.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, maxResults * 5);
    const metadata = await Promise.all(
      candidates.map(([chunkId]) => getDocumentMetadata(chunkId, env))
    );

    return candidates
      .map(([chunkId, score], index) => ({
        chunkId,
        score,
        metadata: metadata[index] || {},
        method: 'keyword',
        matchedTerms: queryTerms
      }))
      .filter(result => passesFilters(result.metadata, filters))
      .slice(0, maxResults);
  } catch (error) {
    console.error('Keyword search error:', error);
    return [];
  }
}

/**
 * Generate query embedding through the configured embedding endpoint.
 */
async function generateQueryEmbedding(query, env) {
  const embeddingUrl = env.EMBEDDING_API_URL;
  const embeddingModel = env.EMBEDDING_MODEL || 'text-embedding-3-small';

  if (!embeddingUrl || !env.EMBEDDING_API_KEY) {
    console.warn('Embedding endpoint is not configured');
    return null;
  }

  try {
    const response = await fetch(embeddingUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.EMBEDDING_API_KEY}`
      },
      body: JSON.stringify({
        input: query,
        model: embeddingModel,
        dimensions: 384
      })
    });

    if (!response.ok) {
      console.error('Embedding API failed with status %s', response.status);
      return null;
    }

    const data = await response.json();
    
    if (data.data && data.data.length > 0) {
      return data.data[0].embedding;
    }

    console.error('Embedding API returned an unexpected response shape');
    return null;
    
  } catch (error) {
    console.error('Embedding generation failed:', error);
    return null;
  }
}

/**
 * Tokenize query for keyword search
 */
function tokenizeQuery(query) {
  if (!query) return [];
  
  // Convert to lowercase and extract alphanumeric tokens
  const tokens = query.toLowerCase()
    .replace(/[^a-z0-9\s_]/g, ' ')
    .split(/\s+/)
    .filter(token => token.length >= 2);

  return [...new Set(tokens)];
}

/**
 * Get BM25 scores for a specific term from KV
 */
async function getBM25ScoresForTerm(term, env) {
  try {
    const termData = await env.SENTRY_KV.get(`bm25:term:${term}`, 'json');
    return termData;
  } catch (error) {
    console.error(`Error getting BM25 data for term ${term}:`, error);
    return null;
  }
}

/**
 * Get document metadata from KV
 */
async function getDocumentMetadata(chunkId, env) {
  try {
    const docData = await env.SENTRY_KV.get(`doc:${chunkId}`, 'json');
    return docData?.metadata || {};
  } catch (error) {
    console.error(`Error getting metadata for document ${chunkId}:`, error);
    return {};
  }
}

/**
 * Get full document content from KV
 */
async function getDocumentContent(chunkId, env) {
  try {
    const docData = await env.SENTRY_KV.get(`doc:${chunkId}`, 'json');
    if (!docData) return { content: '', enrichedContent: '', metadata: {} };
    
    return {
      content: docData.content || '',
      enrichedContent: docData.enrichedContent || '',
      metadata: docData.metadata || {}
    };
  } catch (error) {
    console.error(`Error getting content for document ${chunkId}:`, error);
    return { content: '', enrichedContent: '', metadata: {} };
  }
}

/**
 * Check if document passes filters
 */
function passesFilters(metadata, filters) {
  if (filters.companies && filters.companies.length > 0) {
    if (!filters.companies.includes(metadata.company)) {
      return false;
    }
  }

  if (filters.years && filters.years.length > 0) {
    if (!filters.years.includes(metadata.year)) {
      return false;
    }
  }

  if (filters.techniques && filters.techniques.length > 0) {
    const docTechniques = metadata.ml_techniques || [];
    if (!filters.techniques.some(tech => docTechniques.includes(tech))) {
      return false;
    }
  }

  return true;
}

/**
 * Build Pinecone filter from search filters
 */
function buildPineconeFilter(filters) {
  const pineconeFilter = {};

  if (filters.companies && filters.companies.length > 0) {
    pineconeFilter.company = { $in: filters.companies };
  }

  if (filters.years && filters.years.length > 0) {
    pineconeFilter.year = { $in: filters.years };
  }

  if (filters.techniques && filters.techniques.length > 0) {
    pineconeFilter.ml_techniques = { $in: filters.techniques };
  }

  return Object.keys(pineconeFilter).length > 0 ? pineconeFilter : undefined;
}

/**
 * Combine search results from vector and keyword searches
 */
async function combineSearchResults(
  searchResults,
  hybridWeights,
  requireBothMethods,
  maxResults,
  env
) {
  const combinedResults = new Map();

  // Process each query's results
  for (const queryResult of searchResults) {
    const { vectorResults, keywordResults } = queryResult;

    // Add vector results
    for (const result of vectorResults) {
      const chunkId = result.chunkId;
      if (combinedResults.has(chunkId)) {
        const existing = combinedResults.get(chunkId);
        existing.scores.vectorScore = Math.max(existing.scores.vectorScore, result.score);
        existing.retrievalMethod = 'hybrid';
      } else {
        combinedResults.set(chunkId, {
          chunkId: result.chunkId,
          content: '', // Will be populated later
          enrichedContent: '', // Will be populated later
          metadata: formatMetadata(result.metadata),
          scores: {
            vectorScore: result.score,
            keywordScore: 0,
            hybridScore: 0,
            applicabilityScore: 0
          },
          retrievalMethod: 'vector',
          matchedTerms: []
        });
      }
    }

    // Add keyword results
    for (const result of keywordResults) {
      const chunkId = result.chunkId;
      if (combinedResults.has(chunkId)) {
        const existing = combinedResults.get(chunkId);
        existing.scores.keywordScore = Math.max(existing.scores.keywordScore, result.score);
        existing.retrievalMethod = 'hybrid';
        existing.matchedTerms = [...new Set([...existing.matchedTerms, ...result.matchedTerms])];
      } else {
        combinedResults.set(chunkId, {
          chunkId: result.chunkId,
          content: '', // Will be populated later
          enrichedContent: '', // Will be populated later
          metadata: formatMetadata(result.metadata),
          scores: {
            vectorScore: 0,
            keywordScore: result.score,
            hybridScore: 0,
            applicabilityScore: 0
          },
          retrievalMethod: 'keyword',
          matchedTerms: result.matchedTerms || []
        });
      }
    }
  }

  // Calculate hybrid scores and filter if required
  let results = Array.from(combinedResults.values());
  
  for (const result of results) {
    // Calculate hybrid score using weighted combination
    result.scores.hybridScore = 
      (result.scores.vectorScore * hybridWeights.vector) +
      (result.scores.keywordScore * hybridWeights.keyword);

    // Calculate applicability score (simplified)
    result.scores.applicabilityScore = result.retrievalMethod === 'hybrid' ? 0.8 : 0.6;
  }

  if (requireBothMethods) {
    results = results.filter(result => result.retrievalMethod === 'hybrid');
  }

  results = results
    .sort((a, b) => b.scores.hybridScore - a.scores.hybridScore)
    .slice(0, maxResults);

  const contentResults = await Promise.all(
    results.map(result => getDocumentContent(result.chunkId, env))
  );
  results.forEach((result, index) => {
    const contentData = contentResults[index];
    result.content = contentData.content;
    result.enrichedContent = contentData.enrichedContent;
    result.metadata = { ...result.metadata, ...formatMetadata(contentData.metadata) };
  });

  return results;
}

/**
 * Format metadata for response
 */
function formatMetadata(metadata) {
  return {
    sourceTitle: metadata.source_title || '',
    sourceUrl: metadata.source_url || '',
    company: metadata.company || '',
    year: metadata.year || '',
    mlTechniques: metadata.ml_techniques || [],
    keywords: metadata.keywords || [],
    chunkSummary: metadata.chunk_summary || '',
    chunkIndex: metadata.chunk_index || 0
  };
}

/**
 * Vector Search Handler
 */
async function handleVectorSearch(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'METHOD_NOT_ALLOWED' }, 405);
  }

  try {
    const body = await request.json();
    const query = normalizeQuery(body.query);

    if (!query) {
      return jsonResponse(
        { error: 'INVALID_REQUEST', message: 'A valid query is required' },
        400
      );
    }

    const maxResults = normalizeMaxResults(body.maxResults);
    const filters = normalizeFilters(body.filters);
    const results = await performVectorSearch(query, maxResults, filters, env);
    return jsonResponse({ results });
  } catch (error) {
    console.error('Vector search error:', error);
    return jsonResponse({ error: 'SEARCH_FAILED' }, 500);
  }
}

/**
 * Keyword Search Handler
 */
async function handleKeywordSearch(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'METHOD_NOT_ALLOWED' }, 405);
  }

  try {
    const body = await request.json();
    const query = normalizeQuery(body.query);

    if (!query) {
      return jsonResponse(
        { error: 'INVALID_REQUEST', message: 'A valid query is required' },
        400
      );
    }

    const maxResults = normalizeMaxResults(body.maxResults);
    const filters = normalizeFilters(body.filters);
    const results = await performKeywordSearch(query, maxResults, filters, env);
    return jsonResponse({ results });
  } catch (error) {
    console.error('Keyword search error:', error);
    return jsonResponse({ error: 'SEARCH_FAILED' }, 500);
  }
}

/**
 * Metadata handler
 */
async function handleMetadata(request, env, storageKey, responseKey) {
  if (request.method !== 'GET') {
    return jsonResponse({ error: 'METHOD_NOT_ALLOWED' }, 405);
  }
  try {
    const data = await env.SENTRY_KV.get(storageKey, 'json');
    return jsonResponse(data || { [responseKey]: [] });
  } catch (error) {
    console.error('Metadata read failed:', error);
    return jsonResponse({ error: 'METADATA_UNAVAILABLE' }, 500);
  }
}

/**
 * Utility function to get CORS headers
 */
function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

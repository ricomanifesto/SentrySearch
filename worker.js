/**
 * Cloudflare Workers - SentrySearch Hybrid Search
 * 
 * Implements hybrid vector + keyword search using Pinecone and Cloudflare KV
 * for production-ready ML threat intelligence retrieval.
 */

// Pinecone client configuration will be accessed via environment

/**
 * Main request handler
 */
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS headers for all responses
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
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
        response = await handleMetadataCompanies(request, env);
        break;
      case '/metadata/years':
        response = await handleMetadataYears(request, env);
        break;
      case '/metadata/techniques':
        response = await handleMetadataTechniques(request, env);
        break;
      case '/health':
        response = new Response(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
        break;
      case '/debug-pinecone':
        try {
          const testQuery = "test";
          console.log('Testing Pinecone connection...');
          console.log('PINECONE_API_KEY available:', !!env.PINECONE_API_KEY);
          console.log('PINECONE_INDEX_HOST available:', !!env.PINECONE_INDEX_HOST);
          console.log('PINECONE_INDEX_HOST value:', env.PINECONE_INDEX_HOST);
          console.log('OPENAI_API_KEY available:', !!env.OPENAI_API_KEY);
          
          const embedding = await generateQueryEmbedding(testQuery, env);
          console.log('Generated embedding:', !!embedding, embedding ? embedding.length : 'null');
          
          if (embedding) {
            const pineconeQuery = {
              vector: embedding,
              topK: 1,
              includeMetadata: true,
              includeValues: false
            };
            
            console.log('Querying Pinecone...');
            const pineconeResponse = await fetch(`${env.PINECONE_INDEX_HOST}/query`, {
              method: 'POST',
              headers: {
                'Api-Key': env.PINECONE_API_KEY,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify(pineconeQuery)
            });
            
            console.log('Pinecone response status:', pineconeResponse.status);
            const pineconeData = await pineconeResponse.json();
            console.log('Pinecone data:', JSON.stringify(pineconeData));
            
            response = new Response(JSON.stringify({
              embedding_generated: !!embedding,
              embedding_dimensions: embedding ? embedding.length : null,
              pinecone_status: pineconeResponse.status,
              pinecone_data: pineconeData,
              secrets_available: {
                PINECONE_API_KEY: !!env.PINECONE_API_KEY,
                PINECONE_INDEX_HOST: !!env.PINECONE_INDEX_HOST,
                PINECONE_INDEX_HOST_VALUE: env.PINECONE_INDEX_HOST,
                OPENAI_API_KEY: !!env.OPENAI_API_KEY
              }
            }), {
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          } else {
            response = new Response(JSON.stringify({
              error: 'Failed to generate embedding',
              secrets_available: {
                PINECONE_API_KEY: !!env.PINECONE_API_KEY,
                PINECONE_INDEX_HOST: !!env.PINECONE_INDEX_HOST,
                OPENAI_API_KEY: !!env.OPENAI_API_KEY
              }
            }), {
              status: 500,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
        } catch (error) {
          console.error('Debug error:', error);
          response = new Response(JSON.stringify({
            error: error.message,
            stack: error.stack,
            debug_info: {
              PINECONE_API_KEY: !!env.PINECONE_API_KEY,
              PINECONE_INDEX_HOST: !!env.PINECONE_INDEX_HOST,
              PINECONE_INDEX_HOST_VALUE: env.PINECONE_INDEX_HOST,
              OPENAI_API_KEY: !!env.OPENAI_API_KEY
            }
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        break;
      case '/debug-doc':
        const chunkId = url.searchParams.get('chunkId') || 'Netflix_2019_3_aef2991b';
        try {
          const docContent = await getDocumentContent(chunkId, env);
          response = new Response(JSON.stringify({
            chunkId,
            hasContent: !!docContent.content,
            contentLength: docContent.content.length,
            enrichedLength: docContent.enrichedContent.length,
            metadata: docContent.metadata,
            contentPreview: docContent.content.substring(0, 200)
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (error) {
          response = new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        break;
      case '/debug-search':
        const debugQuery = url.searchParams.get('q') || 'Netflix';
        try {
          const keywordResults = await performKeywordSearch(debugQuery, 1, {}, env);
          const debugInfo = {
            query: debugQuery,
            resultsCount: keywordResults.length,
            firstResult: keywordResults[0] || null,
            hasChunkId: keywordResults[0] ? !!keywordResults[0].chunkId : false,
            resultKeys: keywordResults[0] ? Object.keys(keywordResults[0]) : [],
            chunkIdValue: keywordResults[0] ? keywordResults[0].chunkId : 'undefined',
            chunkIdType: keywordResults[0] ? typeof keywordResults[0].chunkId : 'undefined',
            fullResult: keywordResults[0] || null
          };
          if (keywordResults[0] && keywordResults[0].chunkId) {
            const docContent = await getDocumentContent(keywordResults[0].chunkId, env);
            debugInfo.contentCheck = {
              chunkId: keywordResults[0].chunkId,
              hasContent: !!docContent.content,
              contentLength: docContent.content.length
            };
          } else if (keywordResults[0]) {
            debugInfo.contentCheck = { error: "No chunkId in result" };
          }
          response = new Response(JSON.stringify(debugInfo), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (error) {
          response = new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        break;
      default:
        response = new Response('Not Found', { status: 404, headers: corsHeaders });
    }

    return response;

  } catch (error) {
    console.error('Request handling error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: error.message,
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

/**
 * Hybrid Search Handler - Combines vector and keyword search
 */
async function handleHybridSearch(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const startTime = Date.now();
  
  try {
    const body = await request.json();
    const {
      queries = [],
      maxResults = 10,
      hybridWeights = { vector: 0.6, keyword: 0.4 },
      filters = {},
      requireBothMethods = false
    } = body;

    if (!queries || queries.length === 0) {
      return new Response(JSON.stringify({
        error: 'INVALID_REQUEST',
        message: 'At least one query is required'
      }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // Perform parallel searches
    const searchPromises = queries.map(query => performHybridSearchForQuery(query, maxResults, filters, env));
    const searchResults = await Promise.all(searchPromises);

    // Combine and deduplicate results
    const combinedResults = await combineSearchResults(searchResults, hybridWeights, requireBothMethods, env);

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

    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders() }
    });

  } catch (error) {
    console.error('Hybrid search error:', error);
    return new Response(JSON.stringify({
      error: 'SEARCH_FAILED',
      message: error.message
    }), { status: 500, headers: { 'Content-Type': 'application/json' } });
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
    // Generate embedding for the query
    console.log(`Generating embedding for query: "${query}"`);
    const queryEmbedding = await generateQueryEmbedding(query, env);
    
    // Return empty results if no embedding service is configured
    if (!queryEmbedding) {
      console.log('Vector search skipped - no embedding generated');
      return [];
    }
    
    console.log(`Generated embedding with ${queryEmbedding.length} dimensions`);

    // Prepare Pinecone query
    const pineconeQuery = {
      vector: queryEmbedding,
      topK: maxResults,
      includeMetadata: true,
      includeValues: false
    };

    // Add filters if provided
    if (filters && Object.keys(filters).length > 0) {
      pineconeQuery.filter = buildPineconeFilter(filters);
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
      const errorText = await response.text();
      console.error(`Pinecone query failed: ${response.status} - ${errorText}`);
      throw new Error(`Pinecone query failed: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    console.log(`Pinecone raw response:`, JSON.stringify(data));
    console.log(`Pinecone response: ${data.matches?.length || 0} matches found`);
    
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
    // Tokenize query
    const queryTerms = tokenizeQuery(query);
    if (queryTerms.length === 0) return [];

    // Get BM25 scores for each term
    const termPromises = queryTerms.map(term => getBM25ScoresForTerm(term, env));
    const termResults = await Promise.all(termPromises);

    // Combine scores by document
    const documentScores = new Map();
    const documentMetadata = new Map();

    for (let i = 0; i < queryTerms.length; i++) {
      const term = queryTerms[i];
      const termData = termResults[i];
      
      if (termData && termData.postingsList) {
        for (const posting of termData.postingsList) {
          const chunkId = posting.chunkId || posting.chunk_id; // Try both field names
          const score = posting.score;

          // Get document metadata for all results
          if (!documentMetadata.has(chunkId)) {
            const docMetadata = await getDocumentMetadata(chunkId, env);
            documentMetadata.set(chunkId, docMetadata);
            
            // Apply filters if specified
            if (filters && Object.keys(filters).length > 0) {
              if (!passesFilters(docMetadata, filters)) {
                continue;
              }
            }
          }

          // Accumulate BM25 scores
          if (documentScores.has(chunkId)) {
            documentScores.set(chunkId, documentScores.get(chunkId) + score);
          } else {
            documentScores.set(chunkId, score);
          }
        }
      }
    }

    // Convert to results array and sort
    const entries = Array.from(documentScores.entries());
    
    const results = entries
      .map(([chunkId, score]) => {
        // Ensure chunkId is defined and not null
        const safeChunkId = chunkId || 'unknown';
        return {
          chunkId: safeChunkId,
          score: score,
          metadata: documentMetadata.get(chunkId) || {},
          method: 'keyword',
          matchedTerms: queryTerms
        };
      })
      .filter(result => result.chunkId !== 'unknown') // Remove invalid results
      .sort((a, b) => b.score - a.score)
      .slice(0, maxResults);

    return results;

  } catch (error) {
    console.error('Keyword search error:', error);
    return [];
  }
}

/**
 * Generate query embedding (mock implementation)
 * In production, this would call an embedding service
 */
async function generateQueryEmbedding(query, env) {
  // Use OpenAI embeddings (text-embedding-3-small with 384 dimensions)
  // This matches the 384-dimensional embeddings used in ChromaDB migration
  
  try {
    const response = await fetch('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        input: query,
        model: 'text-embedding-3-small',
        dimensions: 384
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('OpenAI API error:', response.status, errorText);
      return null;
    }

    const data = await response.json();
    
    if (data.data && data.data.length > 0) {
      const embedding = data.data[0].embedding;
      console.log(`Generated ${embedding.length}-dimensional embedding for: "${query}"`);
      return embedding; // Should be 384-dimensional
    }
    
    console.error('Unexpected embedding format from OpenAI:', data);
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

  return tokens;
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
async function combineSearchResults(searchResults, hybridWeights, requireBothMethods, env) {
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

  // Fetch document content for all unique chunk IDs
  const chunkIds = Array.from(combinedResults.keys());
  const contentPromises = chunkIds.map(chunkId => getDocumentContent(chunkId, env));
  const contentResults = await Promise.all(contentPromises);

  // Populate content in results
  for (let i = 0; i < chunkIds.length; i++) {
    const chunkId = chunkIds[i];
    const contentData = contentResults[i];
    const result = combinedResults.get(chunkId);
    
    result.content = contentData.content;
    result.enrichedContent = contentData.enrichedContent;
    // Merge metadata (keep existing, add from content)
    result.metadata = { ...result.metadata, ...formatMetadata(contentData.metadata) };
  }

  // Calculate hybrid scores and filter if required
  const results = Array.from(combinedResults.values());
  
  for (const result of results) {
    // Calculate hybrid score using weighted combination
    result.scores.hybridScore = 
      (result.scores.vectorScore * hybridWeights.vector) +
      (result.scores.keywordScore * hybridWeights.keyword);

    // Calculate applicability score (simplified)
    result.scores.applicabilityScore = result.retrievalMethod === 'hybrid' ? 0.8 : 0.6;
  }

  // Filter results if both methods are required
  if (requireBothMethods) {
    return results.filter(result => result.retrievalMethod === 'hybrid');
  }

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
    return new Response('Method Not Allowed', { status: 405 });
  }

  try {
    const body = await request.json();
    const { query, maxResults = 10, filters = {} } = body;

    if (!query) {
      return new Response(JSON.stringify({
        error: 'INVALID_REQUEST',
        message: 'Query is required'
      }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    const results = await performVectorSearch(query, maxResults, filters, env);

    return new Response(JSON.stringify({ results }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders() }
    });

  } catch (error) {
    console.error('Vector search error:', error);
    return new Response(JSON.stringify({
      error: 'SEARCH_FAILED',
      message: error.message
    }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

/**
 * Keyword Search Handler
 */
async function handleKeywordSearch(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  try {
    const body = await request.json();
    const { query, maxResults = 10, filters = {} } = body;

    if (!query) {
      return new Response(JSON.stringify({
        error: 'INVALID_REQUEST',
        message: 'Query is required'
      }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    const results = await performKeywordSearch(query, maxResults, filters, env);

    return new Response(JSON.stringify({ results }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders() }
    });

  } catch (error) {
    console.error('Keyword search error:', error);
    return new Response(JSON.stringify({
      error: 'SEARCH_FAILED',
      message: error.message
    }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

/**
 * Metadata Handlers
 */
async function handleMetadataCompanies(request, env) {
  try {
    const companiesData = await env.SENTRY_KV.get('meta:companies', 'json');
    return new Response(JSON.stringify(companiesData || { companies: [] }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders() }
    });
  } catch (error) {
    console.error('Get companies error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get companies' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleMetadataYears(request, env) {
  try {
    const yearsData = await env.SENTRY_KV.get('meta:years', 'json');
    return new Response(JSON.stringify(yearsData || { years: [] }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders() }
    });
  } catch (error) {
    console.error('Get years error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get years' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleMetadataTechniques(request, env) {
  try {
    const techniquesData = await env.SENTRY_KV.get('meta:techniques', 'json');
    return new Response(JSON.stringify(techniquesData || { techniques: [] }), {
      headers: { 'Content-Type': 'application/json', ...getCorsHeaders() }
    });
  } catch (error) {
    console.error('Get techniques error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get techniques' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
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
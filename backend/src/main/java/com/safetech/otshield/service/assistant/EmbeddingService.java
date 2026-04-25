package com.safetech.otshield.service.assistant;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Turns text into embeddings by delegating to {@link OllamaClient}, with a
 * small in-memory cache so repeated queries (the user hammering the
 * assistant with the same question, or the ingester re-running on the same
 * text) don't hit the model twice. The cache is keyed by the raw prompt
 * string plus the current embedding model name so swapping models
 * invalidates automatically.
 *
 * <p>The cache is intentionally unbounded - embedding vectors are ~3 KB
 * each and the knowledge base is measured in hundreds of chunks, so even
 * with aggressive query caching we're well under any reasonable heap
 * budget.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmbeddingService {

    private final OllamaClient ollama;
    private final AssistantProperties props;

    private final ConcurrentMap<String, float[]> cache = new ConcurrentHashMap<>();

    /**
     * Returns the embedding for the given text. Blocks until Ollama replies.
     * Safe to call from any thread.
     */
    public float[] embed(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Cannot embed empty text");
        }
        String key = props.getEmbeddingModel() + "::" + text;
        float[] cached = cache.get(key);
        if (cached != null) return cached;

        float[] vec = ollama.embed(text);
        cache.put(key, vec);
        if (log.isDebugEnabled()) {
            log.debug("Embedded '{}' -> {} dims (cache size {})",
                    text.length() > 40 ? text.substring(0, 40) + "..." : text,
                    vec.length, cache.size());
        }
        return vec;
    }

    /**
     * Drops the cache. Called after re-ingesting the knowledge base so stale
     * query embeddings don't linger.
     */
    public void clearCache() {
        cache.clear();
    }
}

package com.safetech.otshield.service.assistant;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Brute-force cosine-similarity vector store, held in a ConcurrentHashMap
 * keyed by chunk id. For the OTShield knowledge base (expected ~50-500
 * chunks) this is plenty: searching 500 vectors of 768 dims is well under
 * a millisecond on any modern CPU, so the overhead of an ANN index
 * (HNSW / ivfflat) is not worth the operational cost.
 *
 * <p>All state is held in-process, which means:
 * <ul>
 *   <li>Re-embedding runs on every app start (cheap - a handful of seconds)</li>
 *   <li>Horizontal scaling would need each instance to ingest its own copy,
 *       or we swap this out for pgvector</li>
 * </ul>
 */
@Component
@Slf4j
public class InMemoryVectorStore implements VectorStore {

    private final ConcurrentMap<String, Chunk> byId = new ConcurrentHashMap<>();

    @Override
    public void upsert(Chunk chunk) {
        byId.put(chunk.id(), chunk);
    }

    @Override
    public void deleteBySource(String source) {
        byId.values().removeIf(c -> c.source().equals(source));
    }

    @Override
    public void clear() {
        byId.clear();
    }

    @Override
    public int size() {
        return byId.size();
    }

    @Override
    public List<ScoredChunk> search(float[] queryEmbedding, int topK, double minScore) {
        if (queryEmbedding == null || queryEmbedding.length == 0 || byId.isEmpty()) {
            return List.of();
        }
        final double qNorm = l2Norm(queryEmbedding);
        if (qNorm == 0.0) return List.of();

        List<ScoredChunk> scored = new ArrayList<>(byId.size());
        for (Chunk c : byId.values()) {
            if (c.embedding() == null || c.embedding().length != queryEmbedding.length) {
                continue;
            }
            double cosine = cosineSimilarity(queryEmbedding, qNorm, c.embedding());
            if (cosine >= minScore) {
                scored.add(new ScoredChunk(c, cosine));
            }
        }
        scored.sort(Comparator.comparingDouble(ScoredChunk::score).reversed());
        if (scored.size() > topK) {
            return scored.subList(0, topK);
        }
        return scored;
    }

    /**
     * Cosine similarity with the query norm pre-computed so we don't
     * recalculate it for every chunk on every search.
     */
    private static double cosineSimilarity(float[] q, double qNorm, float[] v) {
        double dot = 0.0;
        double vNorm = 0.0;
        for (int i = 0; i < q.length; i++) {
            dot += (double) q[i] * v[i];
            vNorm += (double) v[i] * v[i];
        }
        vNorm = Math.sqrt(vNorm);
        if (vNorm == 0.0) return 0.0;
        return dot / (qNorm * vNorm);
    }

    private static double l2Norm(float[] v) {
        double s = 0.0;
        for (float f : v) s += (double) f * f;
        return Math.sqrt(s);
    }
}

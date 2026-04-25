package com.safetech.otshield.service.assistant;

import java.util.List;

/**
 * Minimal contract for a semantic search store. Implementations are free to
 * back this with an in-memory list (current default), Lucene, Chroma, or -
 * once PostgreSQL 18 has a working pgvector binary - a SQL table with
 * {@code vector(768)} columns. Keeping the interface tiny means callers
 * never have to care.
 */
public interface VectorStore {

    /**
     * Result of a similarity search. Score is cosine similarity in
     * {@code [-1, 1]}, with 1.0 meaning identical direction.
     */
    record ScoredChunk(Chunk chunk, double score) {}

    /**
     * Insert or replace a chunk by id.
     */
    void upsert(Chunk chunk);

    /**
     * Remove every chunk whose source label equals the given string. Used
     * during re-ingest so we don't accumulate duplicates when a markdown
     * file gets reworded.
     */
    void deleteBySource(String source);

    /**
     * Drop every chunk. Primarily for tests.
     */
    void clear();

    /**
     * Nearest-neighbour search. Returns at most {@code topK} chunks whose
     * cosine similarity to {@code queryEmbedding} is at least
     * {@code minScore}, sorted by descending similarity.
     */
    List<ScoredChunk> search(float[] queryEmbedding, int topK, double minScore);

    /**
     * Current size - mostly for logging / health endpoints.
     */
    int size();
}

package com.safetech.otshield.service.assistant;

/**
 * A single retrievable unit of knowledge. A Chunk is a paragraph-sized piece
 * of text plus the vector we computed from it and a human-readable source
 * label (usually the markdown file it came from). Chunks live entirely in
 * memory - there is no JPA mapping here. If the knowledge base grows past
 * a few thousand entries we can swap in a pgvector-backed store without
 * touching the callers, because everything flows through {@link VectorStore}.
 *
 * @param id        stable id (file path + ordinal) so re-ingest is idempotent
 * @param source    display label shown in chat citations, e.g. "deception-concepts.md"
 * @param text      raw text of the chunk - never truncated before embedding
 * @param embedding L2-unnormalised embedding vector
 */
public record Chunk(String id, String source, String text, float[] embedding) {}

package com.safetech.otshield.service.research;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns a sequence of extracted PDF pages into retrieval-ready chunks.
 *
 * <p>The algorithm is a token-aware sliding window: we tokenise by
 * whitespace (cheap, language-agnostic, good enough for manual text),
 * emit windows of ~{@link #TARGET_TOKENS} tokens each, and slide forward
 * by ({@link #TARGET_TOKENS} - {@link #OVERLAP_TOKENS}) so adjacent
 * chunks share {@link #OVERLAP_TOKENS} tokens of context. That overlap
 * is what keeps a sentence or table row from being sliced down the
 * middle between two chunks - the retrieval layer will almost always
 * surface at least one chunk that contains the full local context.
 *
 * <p>Page boundaries are preserved: a chunk never straddles a page
 * break, and each chunk carries the page number it came from so the
 * Research Studio UI can deep-link back to the exact source location
 * when it renders a citation.
 *
 * <p>Why whitespace tokens rather than true BPE tokens? Because we're
 * embedding with {@code nomic-embed-text}, whose 8k context easily
 * absorbs any window we produce here, and we'd rather keep the ingest
 * pipeline dependency-free than chase token-parity with a specific
 * tokeniser. If Faz 3.1 introduces a model with a tighter context we
 * can swap in a HuggingFace tokenizers-jvm pass without changing the
 * chunk shape that downstream code sees.
 */
@Component
public class Chunker {

    /** Target size of each chunk, measured in whitespace tokens. */
    private static final int TARGET_TOKENS = 800;

    /** How many tokens each chunk shares with the previous one. */
    private static final int OVERLAP_TOKENS = 100;

    /** A page shorter than this is emitted as a single chunk without windowing. */
    private static final int MIN_WINDOW_TOKENS = 80;

    /** One chunk of text, tagged with its ordinal position and source page. */
    public record Chunk(int ordinal, Integer pageNumber, String text) {}

    /**
     * Chunk a document page-by-page. Ordinals are assigned in reading
     * order across the whole document so the UI can display chunks in
     * the same sequence a human would scroll through the PDF.
     */
    public List<Chunk> chunk(List<PdfExtractor.ExtractedPage> pages) {
        List<Chunk> out = new ArrayList<>();
        int ordinal = 0;
        for (PdfExtractor.ExtractedPage page : pages) {
            List<String> windows = windowize(page.text());
            for (String window : windows) {
                out.add(new Chunk(ordinal++, page.pageNumber(), window));
            }
        }
        return out;
    }

    /**
     * Chunk a flat text document (e.g. plain .txt). Since there are no
     * real page numbers we pass {@code null} through - the UI will fall
     * back to showing just the source filename in citations.
     */
    public List<Chunk> chunkPlainText(String text) {
        List<Chunk> out = new ArrayList<>();
        int ordinal = 0;
        for (String window : windowize(text)) {
            out.add(new Chunk(ordinal++, null, window));
        }
        return out;
    }

    /**
     * Slide a window across the token stream. Short inputs (e.g. a page
     * with a single paragraph) skip the loop and come out whole so we
     * don't over-split content that's already chunk-sized.
     */
    private List<String> windowize(String text) {
        List<String> chunks = new ArrayList<>();
        if (text == null || text.isBlank()) return chunks;

        String[] tokens = text.trim().split("\\s+");
        if (tokens.length <= MIN_WINDOW_TOKENS) {
            chunks.add(String.join(" ", tokens));
            return chunks;
        }

        int step = TARGET_TOKENS - OVERLAP_TOKENS;
        for (int start = 0; start < tokens.length; start += step) {
            int end = Math.min(start + TARGET_TOKENS, tokens.length);
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < end; i++) {
                if (i > start) sb.append(' ');
                sb.append(tokens[i]);
            }
            chunks.add(sb.toString());
            if (end == tokens.length) break;
        }
        return chunks;
    }
}

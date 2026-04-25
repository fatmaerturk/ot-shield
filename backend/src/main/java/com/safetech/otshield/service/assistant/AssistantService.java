package com.safetech.otshield.service.assistant;

import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.repository.research.ResearchDocumentChunkRepository;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Orchestrates the assistant flow:
 *
 * <ol>
 *   <li>Embed the user question via {@link EmbeddingService}</li>
 *   <li>Look up the top-K most relevant chunks in {@link VectorStore}</li>
 *   <li>Build a system prompt that pins the model to OTShield's domain
 *       and injects the retrieved context as numbered passages</li>
 *   <li>Emit a {@code sources} payload so the UI can render citation
 *       pills alongside the assistant's reply</li>
 *   <li>Stream the answer tokens back through {@link OllamaClient}</li>
 * </ol>
 *
 * <p>When the vector store is empty (e.g. fresh install, before anyone
 * uploads reference material) retrieval is a no-op and the assistant
 * answers from base model knowledge plus the static system prompt.
 * When the retriever does find relevant passages it instructs the model
 * to cite them inline as {@code [1]}, {@code [2]}, ... which the
 * frontend maps back to the emitted source list.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AssistantService {

    private final EmbeddingService embeddingService;
    private final VectorStore vectorStore;
    private final OllamaClient ollamaClient;
    private final AssistantProperties props;
    private final ResearchDocumentChunkRepository chunkRepository;
    private final ResearchDocumentRepository documentRepository;

    private static final String SYSTEM_PROMPT = """
            You are OTShield Copilot, an assistant embedded in an Operational
            Technology (OT) cybersecurity platform. OTShield is a
            deception-first defence tool: it runs fake HMIs and honeypots to
            lure attackers, performs deep-packet inspection on Modbus and
            S7Comm traffic, and tracks cases, anomalies, and MITRE ATT&CK for
            ICS engagements.

            Style:
            - Always answer in English, regardless of the user's language.
            - Be concise. One short paragraph is usually enough.
            - Never claim to take actions in the platform. You only explain.

            How to use provided context:
            - When knowledge-base passages are attached to the conversation,
              they are the authoritative source. Read them carefully and
              answer directly from their content - do NOT say you lack
              information about a product or topic that is clearly described
              in the passages.
            - Cite each fact you draw from a passage with a bracketed index
              like [1], [2] matching the passage numbering.
            - If the passages genuinely do not cover the question, say so
              plainly and then share what you know from general ICS / OT
              knowledge without inventing citations.
            - Do not refuse or deflect a question with "I don't have that in
              my database" when passages are attached - use them.

            After your answer, add exactly these two lines (nothing else):
            CONFIDENCE: HIGH|MEDIUM|LOW
            NEEDS_MORE_SOURCES: yes|no
            HIGH = passages directly answer and you cited them.
            MEDIUM = partial coverage or general ICS knowledge mixed in.
            LOW = no passages or they did not cover the topic.
            """;

    /**
     * A single citation surfaced to the frontend alongside the streamed
     * answer. {@code index} matches the {@code [1]}, {@code [2]} markers
     * we ask the model to produce; {@code source} is the filename;
     * {@code page} is the 1-based PDF page (or {@code null} for text
     * documents); {@code snippet} is a short preview so the pill tooltip
     * can show what the citation actually contains; {@code sourceType}
     * is the document's {@link com.safetech.otshield.model.research.ResearchDocument.SourceType}
     * name (e.g. "VENDOR_MANUAL") so the UI can colour the pill.
     */
    public record Citation(int index, String source, Integer page, String snippet,
                           double score, String sourceType) {}

    /**
     * Self-assessment the model appends after its prose answer. Parsed
     * out of the raw stream by {@link #parseAnswerMetadata} and emitted
     * separately to the frontend so the visible text never contains the
     * trailing "CONFIDENCE: ..." / "NEEDS_MORE_SOURCES: ..." lines.
     *
     * <p>Defaults (when the model ignores the instruction or the footer
     * is malformed) are MEDIUM confidence with no "needs more sources"
     * flag - the same conservative middle ground we want a human analyst
     * to assume before verifying.
     */
    public enum Confidence { HIGH, MEDIUM, LOW }

    public record AnswerMetadata(Confidence confidence, boolean needsMoreSources) {
        public static AnswerMetadata defaults() {
            return new AnswerMetadata(Confidence.MEDIUM, false);
        }
    }

    /**
     * Extracts the trailing {@code CONFIDENCE:} / {@code NEEDS_MORE_SOURCES:}
     * footer the system prompt asks for, and returns the cleaned visible
     * answer plus the parsed metadata. The matcher is intentionally
     * lenient: models sometimes drop extra whitespace, lowercase the
     * keywords, or wrap the footer in an unexpected bullet - we still
     * want to recognise and strip it so the user never sees raw tags.
     */
    public record ParsedAnswer(String visibleText, AnswerMetadata metadata) {}

    public static ParsedAnswer parseAnswerMetadata(String raw) {
        if (raw == null || raw.isBlank()) {
            return new ParsedAnswer(raw == null ? "" : raw, AnswerMetadata.defaults());
        }

        // We look for the two tags anywhere in the tail; the model is
        // instructed to put them last, but some llama variants sneak a
        // newline or a trailing period after. Rather than greedy regex
        // over the whole body, walk the last ~400 chars and scan
        // line-by-line from the bottom up.
        int scanFrom = Math.max(0, raw.length() - 400);
        String tail = raw.substring(scanFrom);
        String[] lines = tail.split("\\r?\\n");

        Confidence confidence = null;
        Boolean needsMore = null;
        int footerStartInTail = -1;

        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim()
                    // strip common list / emphasis decorations so
                    // "- CONFIDENCE: HIGH" and "**CONFIDENCE:** HIGH" match.
                    .replaceAll("^[-*>\\s`]+", "")
                    .replaceAll("\\*+", "")
                    .replaceAll("`+", "");
            if (line.isEmpty()) continue;

            String upper = line.toUpperCase();
            if (confidence == null && upper.startsWith("CONFIDENCE:")) {
                String val = line.substring("CONFIDENCE:".length()).trim().toUpperCase();
                // Accept "HIGH", "high", "HIGH." and even "HIGH - because ..."
                for (Confidence c : Confidence.values()) {
                    if (val.startsWith(c.name())) {
                        confidence = c;
                        break;
                    }
                }
                if (confidence != null) {
                    footerStartInTail = tailIndexOf(tail, lines, i);
                }
                continue;
            }
            if (needsMore == null && upper.startsWith("NEEDS_MORE_SOURCES:")) {
                String val = line.substring("NEEDS_MORE_SOURCES:".length()).trim().toLowerCase();
                if (val.startsWith("yes") || val.startsWith("y") || val.startsWith("true")) {
                    needsMore = Boolean.TRUE;
                } else if (val.startsWith("no") || val.startsWith("n") || val.startsWith("false")) {
                    needsMore = Boolean.FALSE;
                }
                if (needsMore != null) {
                    int start = tailIndexOf(tail, lines, i);
                    if (start >= 0 && (footerStartInTail < 0 || start < footerStartInTail)) {
                        footerStartInTail = start;
                    }
                }
                continue;
            }
            // Once we hit a real content line before any of the tags,
            // stop walking up - the footer has to be last.
            if (confidence != null || needsMore != null) break;
        }

        AnswerMetadata meta = new AnswerMetadata(
                confidence == null ? Confidence.MEDIUM : confidence,
                needsMore == null ? false : needsMore
        );

        String visible = raw;
        if (footerStartInTail >= 0) {
            int cut = scanFrom + footerStartInTail;
            visible = raw.substring(0, cut).replaceAll("\\s+$", "");
        }
        return new ParsedAnswer(visible, meta);
    }

    /** Start offset of {@code lines[i]} inside {@code tail}. */
    private static int tailIndexOf(String tail, String[] lines, int targetLine) {
        int offset = 0;
        for (int j = 0; j < targetLine; j++) {
            offset += lines[j].length() + 1; // +1 for the split delimiter
        }
        return offset <= tail.length() ? offset : -1;
    }

    /**
     * Streams the assistant's answer for one user question.
     *
     * <p>Callbacks fire in this order:
     * <ol>
     *   <li>{@code onSources} with the resolved citation list (may be empty)</li>
     *   <li>{@code onToken} zero or more times as the model emits tokens</li>
     *   <li>{@code onComplete} when the stream ends cleanly</li>
     *   <li>{@code onError} if anything blows up at any stage</li>
     * </ol>
     */
    public void streamAnswer(String userQuestion,
                             List<OllamaClient.Message> history,
                             Consumer<List<Citation>> onSources,
                             Consumer<String> onToken,
                             Runnable onComplete,
                             Consumer<Throwable> onError) {
        try {
            List<VectorStore.ScoredChunk> retrieved = retrieve(userQuestion);
            List<Citation> citations = buildCitations(retrieved);
            onSources.accept(citations);

            String systemPrompt = buildSystemPrompt(retrieved);

            List<OllamaClient.Message> messages = new ArrayList<>();
            messages.add(new OllamaClient.Message("system", systemPrompt));
            if (history != null) {
                messages.addAll(history);
            }
            messages.add(new OllamaClient.Message("user", userQuestion));

            if (log.isDebugEnabled()) {
                log.debug("Assistant streaming: question='{}', history={} turns, retrieved={} chunks",
                        userQuestion.length() > 60 ? userQuestion.substring(0, 60) + "..." : userQuestion,
                        history == null ? 0 : history.size(),
                        retrieved.size());
            }

            ollamaClient.streamChat(messages, onToken, onComplete, onError);
        } catch (Exception e) {
            log.error("Assistant streamAnswer failed", e);
            onError.accept(e);
        }
    }

    /**
     * Try retrieval. If the vector store is empty or Ollama is unavailable
     * for embedding we return an empty list and let the model answer from
     * its own knowledge - we never let retrieval failures kill the chat.
     */
    private List<VectorStore.ScoredChunk> retrieve(String question) {
        if (vectorStore.size() == 0) {
            log.info("RAG: vector store is empty - nothing to retrieve for '{}'",
                    question.length() > 60 ? question.substring(0, 60) + "..." : question);
            return List.of();
        }
        try {
            float[] qEmbedding = embeddingService.embed(question);
            // First pull the unfiltered top-K so we can log what the store
            // actually considered; then apply the relevance cut-off. This
            // makes it obvious when the threshold is throwing away useful
            // matches ("we had chunks but all below 0.18") versus when
            // the store really has nothing relevant.
            List<VectorStore.ScoredChunk> unfiltered =
                    vectorStore.search(qEmbedding, props.getRetrievalTopK(), 0.0);
            if (log.isInfoEnabled()) {
                StringBuilder dbg = new StringBuilder("RAG top candidates: ");
                for (VectorStore.ScoredChunk sc : unfiltered) {
                    dbg.append(String.format("%s@%.2f  ", sc.chunk().source(), sc.score()));
                }
                log.info(dbg.toString());
            }
            List<VectorStore.ScoredChunk> kept = new ArrayList<>();
            double threshold = props.getMinRelevance();
            for (VectorStore.ScoredChunk sc : unfiltered) {
                if (sc.score() >= threshold) kept.add(sc);
            }
            if (kept.isEmpty() && !unfiltered.isEmpty()) {
                log.info("RAG: {} candidates found but all below threshold {} - answering without context",
                        unfiltered.size(), threshold);
            }
            return kept;
        } catch (Exception e) {
            log.warn("RAG retrieval failed, answering without context: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Resolve each retrieved chunk into a {@link Citation}, enriching
     * with page numbers pulled from the research-chunk table when the
     * chunk id is recognised as a Research Studio entry.
     */
    private List<Citation> buildCitations(List<VectorStore.ScoredChunk> retrieved) {
        if (retrieved.isEmpty()) return List.of();

        List<String> researchIds = new ArrayList<>();
        for (VectorStore.ScoredChunk sc : retrieved) {
            String id = sc.chunk().id();
            if (id != null && id.contains("::")) researchIds.add(id);
        }

        Map<String, Integer> pageByChunkId = new HashMap<>();
        Map<String, String> documentIdByChunkId = new HashMap<>();
        if (!researchIds.isEmpty()) {
            try {
                chunkRepository.findByIdIn(researchIds).forEach(r -> {
                    pageByChunkId.put(r.getId(), r.getPageNumber());
                    documentIdByChunkId.put(r.getId(), r.getDocumentId());
                });
            } catch (Exception e) {
                log.debug("Could not resolve chunk metadata: {}", e.getMessage());
            }
        }

        // Fetch source-type for each distinct document referenced by
        // this retrieval. One bulk findAllById keeps us to a single
        // extra query even when 4-6 chunks come from different docs.
        Map<String, String> sourceTypeByDocId = new HashMap<>();
        if (!documentIdByChunkId.isEmpty()) {
            try {
                Set<String> distinctDocs = new HashSet<>(documentIdByChunkId.values());
                documentRepository.findAllById(distinctDocs).forEach(d -> {
                    ResearchDocument.SourceType st = d.getSourceType();
                    sourceTypeByDocId.put(d.getId(),
                            st == null ? ResearchDocument.SourceType.UNKNOWN.name() : st.name());
                });
            } catch (Exception e) {
                log.debug("Could not resolve document source types: {}", e.getMessage());
            }
        }

        List<Citation> out = new ArrayList<>(retrieved.size());
        int idx = 1;
        for (VectorStore.ScoredChunk sc : retrieved) {
            Chunk c = sc.chunk();
            Integer page = pageByChunkId.get(c.id());
            String docId = documentIdByChunkId.get(c.id());
            String sourceType = docId == null ? null : sourceTypeByDocId.get(docId);
            if (sourceType == null) sourceType = ResearchDocument.SourceType.UNKNOWN.name();
            out.add(new Citation(idx++, c.source(), page, snippet(c.text()),
                    sc.score(), sourceType));
        }
        return out;
    }

    /** ~180 char preview so citation tooltips stay readable. */
    private static String snippet(String text) {
        if (text == null) return "";
        String cleaned = text.replaceAll("\\s+", " ").trim();
        return cleaned.length() <= 180 ? cleaned : cleaned.substring(0, 180) + "...";
    }

    /**
     * Budget for the whole context window. Must fit inside
     * {@code num_ctx=2048} tokens together with system prompt, history,
     * question, and generation headroom - so we cap the RAG passages at
     * ~2400 characters (~600 tokens) total.
     */
    private static final int MAX_CONTEXT_CHARS = 2400;
    /** Per-passage char cap so one huge chunk can't swallow the budget. */
    private static final int MAX_CHARS_PER_PASSAGE = 600;

    private String buildSystemPrompt(List<VectorStore.ScoredChunk> retrieved) {
        if (retrieved.isEmpty()) {
            return SYSTEM_PROMPT;
        }
        StringBuilder ctx = new StringBuilder(SYSTEM_PROMPT);
        ctx.append("\n\nKnowledge-base passages (cite them as [1], [2], ...):\n");
        int used = 0;
        int i = 1;
        for (VectorStore.ScoredChunk sc : retrieved) {
            if (used >= MAX_CONTEXT_CHARS) break;
            String text = sc.chunk().text();
            if (text == null) continue;
            // Trim runaway whitespace so newlines in PDFs don't waste tokens.
            String compact = text.replaceAll("\\s+", " ").trim();
            if (compact.length() > MAX_CHARS_PER_PASSAGE) {
                compact = compact.substring(0, MAX_CHARS_PER_PASSAGE) + "...";
            }
            // Respect the overall budget - truncate the last passage that
            // would push us over instead of dropping it entirely.
            int remaining = MAX_CONTEXT_CHARS - used;
            if (compact.length() > remaining) {
                compact = compact.substring(0, Math.max(0, remaining - 3)) + "...";
            }
            ctx.append("\n[")
                    .append(i++).append("] ")
                    .append(sc.chunk().source())
                    .append(" (score=").append(String.format("%.2f", sc.score())).append(")\n")
                    .append(compact)
                    .append("\n");
            used += compact.length();
        }
        return ctx.toString();
    }

    public boolean isReady() {
        return ollamaClient.ping();
    }

    public int knowledgeBaseSize() {
        return vectorStore.size();
    }

    /**
     * On startup, fire a trivial chat prompt at Ollama so it pulls the
     * model weights into RAM before a user ever types. Without this the
     * very first question in a fresh session spends 30-60s in apparent
     * dead air while Ollama mmaps ~2 GB of q4 weights, which trips the
     * browser's SSE expectations and the user sees "chat timed out".
     *
     * <p>Runs on a daemon thread so a slow warmup never blocks Spring
     * boot - if Ollama isn't up yet we just log and move on. A
     * follow-up real question will pay the cold-start cost once.
     */
    @PostConstruct
    void warmup() {
        if (!props.isWarmupOnStartup()) return;
        Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "assistant-warmup");
            t.setDaemon(true);
            return t;
        }).submit(() -> {
            try {
                if (!ollamaClient.ping()) {
                    log.info("Assistant warmup skipped: Ollama not reachable yet.");
                    return;
                }
                long t0 = System.currentTimeMillis();
                log.info("Assistant warmup: loading chat model into RAM...");
                List<OllamaClient.Message> msgs = List.of(
                        new OllamaClient.Message("system", "Reply with the single word: ready"),
                        new OllamaClient.Message("user", "ping")
                );
                StringBuilder out = new StringBuilder();
                ollamaClient.streamChat(
                        msgs,
                        out::append,
                        () -> {},
                        err -> log.warn("Assistant warmup error: {}", err.getMessage())
                );
                log.info("Assistant warmup complete in {} ms (reply: '{}')",
                        System.currentTimeMillis() - t0,
                        out.length() > 40 ? out.substring(0, 40) + "..." : out.toString());
            } catch (Exception e) {
                log.warn("Assistant warmup failed: {}", e.getMessage());
            }
        });
    }
}

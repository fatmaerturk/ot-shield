package com.safetech.otshield.service.assistant;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.service.assistant.AssistantService.Confidence;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Generates "alternative theories" for a given assistant answer — the
 * second leg of the HMGCC "alternative theories" requirement. Given the
 * same question and retrieved passages, we ask the model to play devil's
 * advocate and produce 2–3 short contrarian hypotheses, each with a
 * one-line rationale and a self-reported confidence.
 *
 * <p>Kept separate from {@link AssistantService} because the flow here
 * is strictly request/response (not streaming): the researcher clicks
 * "Show alternative theories", we synthesise, we persist the structured
 * list as JSON on the parent message. The UI renders them as collapsible
 * cards; there's no token-by-token display.
 *
 * <p>Runs synchronously on the caller's servlet thread — generation is
 * short (~150 tokens total for 3 alternatives) and capped at 45 seconds.
 * If it times out we return whatever we managed to parse, or an empty
 * list on total failure; the parent answer is never touched.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AlternativesService {

    private final EmbeddingService embeddingService;
    private final VectorStore vectorStore;
    private final OllamaClient ollamaClient;
    private final AssistantProperties props;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * One alternative hypothesis surfaced to the UI. {@code index} is a
     * 1-based rank (most plausible first); {@code rationale} is the
     * model's one-line argument; {@code confidence} mirrors the main
     * answer's self-assessment ramp.
     */
    public record Alternative(int index, String hypothesis, String rationale, Confidence confidence) {}

    private static final String SYSTEM_PROMPT = """
            You are a contrarian review partner for an OT / ICS security
            researcher. You will see a question that a junior analyst
            already asked, and the "primary" answer they received.

            Your job: produce 2 or 3 alternative explanations or
            hypotheses the primary answer might have missed - things a
            skeptical reviewer would suggest before signing off.

            Rules:
            - Each alternative must disagree with, or materially extend,
              the primary answer. No rephrasings of the primary.
            - Keep each one to one short sentence of claim plus one
              short sentence of rationale.
            - Respond ONLY as a numbered list in this exact format:

              1. CLAIM: <the alternative hypothesis>
                 RATIONALE: <why a reviewer would suggest it>
                 CONFIDENCE: HIGH|MEDIUM|LOW

              2. ...

            - Do not add preamble, closing remarks, or citation markers.
            - If the passages genuinely admit no alternatives, return the
              single line "NO ALTERNATIVES" and stop.
            """;

    /**
     * Run the contrarian pass. Returns an empty list on any failure so
     * the caller (controller) never has to worry about exceptions.
     */
    public List<Alternative> generate(String question, String primaryAnswer) {
        try {
            List<VectorStore.ScoredChunk> retrieved = retrieve(question);
            String prompt = buildUserPrompt(question, primaryAnswer, retrieved);

            List<OllamaClient.Message> messages = List.of(
                    new OllamaClient.Message("system", SYSTEM_PROMPT),
                    new OllamaClient.Message("user", prompt)
            );

            StringBuilder buf = new StringBuilder();
            AtomicReference<Throwable> errRef = new AtomicReference<>();
            CountDownLatch done = new CountDownLatch(1);

            long t0 = System.currentTimeMillis();
            ollamaClient.streamChat(
                    messages,
                    buf::append,
                    done::countDown,
                    err -> {
                        errRef.set(err);
                        done.countDown();
                    }
            );
            if (!done.await(45, TimeUnit.SECONDS)) {
                log.warn("Alternatives: generation timed out after 45s, got {} chars", buf.length());
            }
            if (errRef.get() != null) {
                log.warn("Alternatives: generation failed: {}", errRef.get().getMessage());
                return List.of();
            }
            String raw = buf.toString().trim();
            log.info("Alternatives: got {} chars in {} ms", raw.length(), System.currentTimeMillis() - t0);
            return parse(raw);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return List.of();
        } catch (Exception e) {
            log.warn("Alternatives: unexpected failure: {}", e.getMessage());
            return List.of();
        }
    }

    /** Serialise a list of alternatives for storage on ResearchMessage. */
    public String toJson(List<Alternative> alternatives) {
        if (alternatives == null || alternatives.isEmpty()) return null;
        try {
            return objectMapper.writeValueAsString(alternatives);
        } catch (JsonProcessingException e) {
            log.warn("Alternatives: failed to serialise: {}", e.getMessage());
            return null;
        }
    }

    /** Deserialise from storage; returns empty list on any failure. */
    public List<Alternative> fromJson(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return objectMapper.readerForListOf(Alternative.class).readValue(json);
        } catch (Exception e) {
            log.debug("Alternatives: could not parse stored JSON: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    // ------------------------------------------------------------------
    // Retrieval (same as AssistantService — duplicated here rather than
    // coupled so a future refactor to a shared helper is a single move).
    // ------------------------------------------------------------------

    private List<VectorStore.ScoredChunk> retrieve(String question) {
        if (vectorStore.size() == 0) return List.of();
        try {
            float[] qEmbedding = embeddingService.embed(question);
            List<VectorStore.ScoredChunk> unfiltered =
                    vectorStore.search(qEmbedding, props.getRetrievalTopK(), 0.0);
            List<VectorStore.ScoredChunk> kept = new ArrayList<>();
            double threshold = props.getMinRelevance();
            for (VectorStore.ScoredChunk sc : unfiltered) {
                if (sc.score() >= threshold) kept.add(sc);
            }
            return kept;
        } catch (Exception e) {
            log.debug("Alternatives: retrieval failed, continuing without context: {}", e.getMessage());
            return List.of();
        }
    }

    private String buildUserPrompt(String question,
                                   String primaryAnswer,
                                   List<VectorStore.ScoredChunk> retrieved) {
        StringBuilder ctx = new StringBuilder();
        ctx.append("QUESTION: ").append(truncate(question, 400)).append("\n\n");
        ctx.append("PRIMARY ANSWER: ").append(truncate(primaryAnswer, 1200)).append("\n\n");

        if (!retrieved.isEmpty()) {
            ctx.append("KNOWLEDGE-BASE PASSAGES (reference only, no need to cite):\n");
            int budget = 1200;
            int i = 1;
            for (VectorStore.ScoredChunk sc : retrieved) {
                if (budget <= 0) break;
                String text = sc.chunk().text();
                if (text == null) continue;
                String compact = text.replaceAll("\\s+", " ").trim();
                int cap = Math.min(300, budget);
                if (compact.length() > cap) compact = compact.substring(0, cap) + "...";
                ctx.append("[").append(i++).append("] ").append(compact).append("\n");
                budget -= compact.length();
            }
            ctx.append("\n");
        }
        ctx.append("Now produce the 2-3 alternative hypotheses.");
        return ctx.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        String compact = s.replaceAll("\\s+", " ").trim();
        return compact.length() <= max ? compact : compact.substring(0, max) + "...";
    }

    // ------------------------------------------------------------------
    // Parser — intentionally lenient: we'd rather over-accept mis-shaped
    // output than silently drop a valid hypothesis.
    // ------------------------------------------------------------------

    /**
     * Parse the "1. CLAIM: ... / RATIONALE: ... / CONFIDENCE: ..." block
     * format. Works in two passes:
     *   pass 1: split on lines that start with "N." (number dot) to
     *           isolate per-alternative blobs;
     *   pass 2: inside each blob, key-value scan for CLAIM / RATIONALE /
     *           CONFIDENCE - order and casing tolerant.
     */
    public List<Alternative> parse(String raw) {
        if (raw == null) return List.of();
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) return List.of();
        if (trimmed.toUpperCase().startsWith("NO ALTERNATIVES")) return List.of();

        // Split on leading "<digit>." patterns, keeping the lookbehind so
        // the delimiter stays with the next block.
        String[] blocks = trimmed.split("(?m)^\\s*\\d+\\s*[\\.\\)]\\s*");
        List<Alternative> out = new ArrayList<>();
        int idx = 1;
        for (String block : blocks) {
            String body = block.trim();
            if (body.isEmpty()) continue;
            Alternative alt = parseBlock(idx, body);
            if (alt != null) {
                out.add(alt);
                idx++;
            }
            if (idx > 3) break; // Clamp to 3 per spec.
        }
        return out;
    }

    private Alternative parseBlock(int index, String body) {
        String claim = null;
        String rationale = null;
        Confidence conf = null;

        String[] lines = body.split("\\r?\\n");
        // Support both "KEY: value" on separate lines and "KEY: value KEY2: ..."
        // on one line by regex-splitting each line into key chunks.
        StringBuilder currentValue = new StringBuilder();
        String currentKey = null;

        for (String rawLine : lines) {
            String line = rawLine.trim()
                    .replaceAll("^[-*>\\s`]+", "")
                    .replaceAll("\\*+", "")
                    .replaceAll("`+", "");
            if (line.isEmpty()) continue;

            // When a line starts with KEY: we commit whatever we had
            // accumulated into the previous key's slot, then switch.
            Map.Entry<String, String> kv = firstKey(line);
            if (kv != null) {
                if (currentKey != null) {
                    String v = currentValue.toString().trim();
                    switch (currentKey) {
                        case "CLAIM" -> { if (claim == null) claim = v; }
                        case "RATIONALE" -> { if (rationale == null) rationale = v; }
                        case "CONFIDENCE" -> { if (conf == null) conf = parseConfidence(v); }
                        default -> { }
                    }
                }
                currentKey = kv.getKey();
                currentValue = new StringBuilder(kv.getValue());
            } else if (currentKey != null) {
                // Continuation of the previous key's value.
                if (currentValue.length() > 0) currentValue.append(' ');
                currentValue.append(line);
            }
        }
        // Flush the final key.
        if (currentKey != null) {
            String v = currentValue.toString().trim();
            switch (currentKey) {
                case "CLAIM" -> { if (claim == null) claim = v; }
                case "RATIONALE" -> { if (rationale == null) rationale = v; }
                case "CONFIDENCE" -> { if (conf == null) conf = parseConfidence(v); }
                default -> { }
            }
        }

        // Fallback: if the model forgot CLAIM: label, the first non-empty
        // line of the block was probably the claim.
        if (claim == null) {
            for (String rawLine : lines) {
                String line = rawLine.trim().replaceAll("^[-*>\\s`]+", "");
                if (!line.isEmpty()) {
                    claim = stripLeadingKey(line);
                    break;
                }
            }
        }

        if (claim == null || claim.isBlank()) return null;
        return new Alternative(
                index,
                cap(claim, 400),
                rationale == null ? "" : cap(rationale, 500),
                conf == null ? Confidence.MEDIUM : conf
        );
    }

    /** If {@code line} starts with {@code KEY:} returns (KEY, remainder); else null. */
    private static Map.Entry<String, String> firstKey(String line) {
        for (String key : Arrays.asList("CLAIM", "RATIONALE", "CONFIDENCE", "HYPOTHESIS", "REASON")) {
            String upper = line.toUpperCase();
            if (upper.startsWith(key + ":")) {
                String normalised = switch (key) {
                    case "HYPOTHESIS" -> "CLAIM";
                    case "REASON" -> "RATIONALE";
                    default -> key;
                };
                String remainder = line.substring(key.length() + 1).trim();
                return Map.entry(normalised, remainder);
            }
        }
        return null;
    }

    private static Confidence parseConfidence(String v) {
        String upper = v.toUpperCase();
        for (Confidence c : Confidence.values()) {
            if (upper.startsWith(c.name())) return c;
        }
        return null;
    }

    private static String stripLeadingKey(String s) {
        return s.replaceFirst("^(?i)(CLAIM|HYPOTHESIS|RATIONALE|CONFIDENCE|REASON)\\s*:\\s*", "").trim();
    }

    private static String cap(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}

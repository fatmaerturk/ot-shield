package com.safetech.otshield.service.assistant;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Generates short follow-up questions for a finished assistant turn.
 * The HMGCC brief emphasises workflow ergonomics - a tear-down analyst
 * shouldn't have to phrase every next move themselves. Three chip-style
 * suggestions under each answer keep the research loop tight.
 *
 * <p>Implemented as a thin wrapper over {@link OllamaClient} with a
 * compact prompt. No retrieval, no streaming: we want a tiny, low-cost
 * call that finishes in a few seconds. Output is split on newlines and
 * normalised to at most three clean question strings.
 *
 * <p>On any failure we return an empty list; suggestions are
 * nice-to-have and never block the UI.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FollowUpService {

    private final OllamaClient ollamaClient;

    private static final String SYSTEM_PROMPT = """
            You are a research coach for an OT / ICS security analyst
            who just finished asking one question and reading the answer.
            Suggest 3 concise follow-up questions the analyst might
            reasonably ask next to deepen the investigation.

            Rules:
            - Output ONLY the questions, one per line.
            - Each question must be a single sentence, under 12 words.
            - No numbering, no bullets, no preamble, no explanation.
            - Prefer questions that probe vendor-specific details,
              potential vulnerabilities, or verification steps.
            """;

    /**
     * Generate up to 3 follow-up question suggestions. Returns empty
     * on timeout / error.
     *
     * @param question the original user question
     * @param answer the assistant's answer (already with footer stripped)
     */
    public List<String> suggest(String question, String answer) {
        if (question == null || question.isBlank()) return List.of();
        if (answer == null || answer.isBlank()) return List.of();

        String userPrompt = "Question just asked:\n" + truncate(question, 400)
                + "\n\nAssistant answer:\n" + truncate(answer, 1500)
                + "\n\nNow give me 3 short follow-up questions.";

        StringBuilder buf = new StringBuilder();
        AtomicReference<Throwable> errRef = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        long t0 = System.currentTimeMillis();
        try {
            ollamaClient.streamChat(
                    List.of(
                            new OllamaClient.Message("system", SYSTEM_PROMPT),
                            new OllamaClient.Message("user", userPrompt)
                    ),
                    buf::append,
                    done::countDown,
                    err -> {
                        errRef.set(err);
                        done.countDown();
                    }
            );
            if (!done.await(30, TimeUnit.SECONDS)) {
                log.warn("FollowUp suggestion timed out after 30s");
                return List.of();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return List.of();
        } catch (Exception e) {
            log.warn("FollowUp suggestion failed: {}", e.getMessage());
            return List.of();
        }
        if (errRef.get() != null) {
            log.warn("FollowUp suggestion error: {}", errRef.get().getMessage());
            return List.of();
        }

        List<String> suggestions = parse(buf.toString());
        log.info("FollowUp: {} suggestions in {} ms", suggestions.size(),
                System.currentTimeMillis() - t0);
        return suggestions;
    }

    /**
     * Split the raw LLM output into cleaned-up question strings. We're
     * tolerant about bullet / number prefixes because small models
     * frequently add them even when the prompt forbids them.
     */
    public List<String> parse(String raw) {
        if (raw == null) return List.of();
        String[] lines = raw.split("\\r?\\n");
        List<String> out = new ArrayList<>();
        for (String line : lines) {
            String cleaned = line.trim()
                    .replaceAll("^[\\d.)\\-*>\\s`]+", "") // bullets / numbering
                    .replaceAll("\\*+", "")
                    .replaceAll("`+", "")
                    .replace("\"", "")
                    .trim();
            if (cleaned.isEmpty()) continue;
            if (cleaned.length() > 200) cleaned = cleaned.substring(0, 200);
            // Require a question mark - follow-ups without one tend
            // to be preambles ("Here are three...") or stray
            // commentary. This keeps the chip rail clean.
            if (!cleaned.endsWith("?")) continue;
            out.add(cleaned);
            if (out.size() >= 3) break;
        }
        return out;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        String compact = s.replaceAll("\\s+", " ").trim();
        return compact.length() <= max ? compact : compact.substring(0, max) + "...";
    }
}

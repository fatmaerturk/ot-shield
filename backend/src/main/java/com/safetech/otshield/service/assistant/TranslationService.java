package com.safetech.otshield.service.assistant;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Offline translation using the local Ollama chat model. Designed for
 * the HMGCC "multilingual support" requirement - the tear-down assistant
 * needs to explain itself in the researcher's working language without
 * any external API call.
 *
 * <p>We deliberately reuse the chat model rather than deploying a
 * dedicated NMT model (NLLB, M2M-100) because:
 * <ul>
 *   <li>Ollama is already warmed up in RAM - zero extra memory cost.</li>
 *   <li>A translation-only model adds ~1-2 GB to the image.</li>
 *   <li>The chat model can be instructed to preserve domain tokens
 *       (CVE ids, port numbers, citation markers) which matters more
 *       than perfect fluency here.</li>
 * </ul>
 *
 * <p>Cache is a small LRU keyed by {@code (text-hash, targetLang)} so
 * reopening a thread doesn't re-translate identical assistant bubbles.
 * The cache lives in memory only; not persisted across restarts.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TranslationService {

    private final OllamaClient ollamaClient;

    /**
     * Bounded LRU cache. {@link LinkedHashMap} with access-order is the
     * standard JDK idiom - we override {@link LinkedHashMap#removeEldestEntry}
     * to cap at a few hundred entries so long sessions don't leak RAM.
     */
    @SuppressWarnings("serial")
    private final Map<String, String> cache = Collections.synchronizedMap(
            new LinkedHashMap<>(256, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                    return size() > 256;
                }
            });

    private static final String SYSTEM_PROMPT = """
            You are a technical translator for an industrial-cybersecurity
            research tool. Translate the given text into the target
            language with these strict rules:
            - Preserve every citation marker exactly as written: [1], [2],
              [3], etc.
            - Preserve every number, port, IP address, MAC address, CVE
              id, file name, version string, and product name verbatim.
              Do not localise digits or dots.
            - Preserve acronyms (PLC, HMI, ICS, SCADA, TCP, UDP, HTTP,
              SSH, Modbus, S7Comm, OPC UA, etc.).
            - Translate only the natural-language prose around those
              tokens.
            - Output ONLY the translated text. No preamble, no
              explanation, no quotes around the output.
            """;

    /**
     * Supported target languages. The UI exposes these as a dropdown.
     * Adding a language means adding a name here and in the frontend
     * {@code LANG_LABELS} map; the prompt template adapts automatically.
     */
    public enum Language {
        EN("English"), TR("Turkish"), DE("German"), FR("French"), ES("Spanish");

        private final String fullName;
        Language(String fullName) { this.fullName = fullName; }
        public String fullName() { return fullName; }
    }

    /**
     * Translate {@code text} into {@code target}. Returns the cached
     * value when the same text was translated earlier in this session.
     * On any failure (Ollama offline, timeout, interruption) returns
     * the original text so the caller can keep rendering - translation
     * is a nice-to-have, not load-bearing.
     */
    public String translate(String text, Language target) {
        if (text == null || text.isBlank()) return text == null ? "" : text;
        if (target == null) return text;

        String cacheKey = target.name() + "|" + Integer.toHexString(text.hashCode()) + "|" + text.length();
        String hit = cache.get(cacheKey);
        if (hit != null) {
            log.debug("Translation cache hit for {} chars -> {}", text.length(), target);
            return hit;
        }

        String userPrompt = "Target language: " + target.fullName() + "\n\nText:\n" + text;

        StringBuilder buf = new StringBuilder();
        AtomicReference<Throwable> errRef = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        long t0 = System.currentTimeMillis();
        try {
            ollamaClient.streamChat(
                    java.util.List.of(
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
            if (!done.await(45, TimeUnit.SECONDS)) {
                log.warn("Translation timed out after 45s; returning original ({} chars)", text.length());
                return text;
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return text;
        } catch (Exception e) {
            log.warn("Translation failed: {}", e.getMessage());
            return text;
        }

        if (errRef.get() != null) {
            log.warn("Translation error: {}", errRef.get().getMessage());
            return text;
        }

        String translated = buf.toString().trim();
        if (translated.isEmpty()) return text;
        cache.put(cacheKey, translated);
        log.info("Translated {} -> {} chars in {} ms", text.length(), translated.length(),
                System.currentTimeMillis() - t0);
        return translated;
    }

    /** Exposed so tests and diagnostics can clear the cache explicitly. */
    public void clearCache() { cache.clear(); }
}

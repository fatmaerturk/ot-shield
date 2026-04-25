package com.safetech.otshield.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.dto.assistant.ChatRequestDTO;
import com.safetech.otshield.service.assistant.AssistantService;
import com.safetech.otshield.service.assistant.AssistantService.AnswerMetadata;
import com.safetech.otshield.service.assistant.AssistantService.Citation;
import com.safetech.otshield.service.assistant.AssistantService.ParsedAnswer;
import com.safetech.otshield.service.assistant.OllamaClient;
import com.safetech.otshield.service.assistant.SourceCrossCheckService;
import com.safetech.otshield.service.assistant.SourceCrossCheckService.ConsistencyWarning;
import com.safetech.otshield.service.assistant.FollowUpService;
import com.safetech.otshield.service.assistant.TranslationService;
import com.safetech.otshield.service.research.ThreadService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * REST surface for the OTShield AI assistant.
 *
 * <ul>
 *   <li>{@code POST /api/assistant/chat} streams tokens as
 *       Server-Sent Events. The frontend consumes this via {@code EventSource}
 *       (or a fetch-based reader for POST-SSE).</li>
 *   <li>{@code GET /api/assistant/health} lets the UI decide whether to show
 *       "assistant unavailable" before the user types.</li>
 * </ul>
 *
 * <p>We lean on {@link SseEmitter} instead of WebFlux because the rest of
 * the backend is servlet-based and mixing runtimes isn't worth it for one
 * endpoint. A single cached thread pool dispatches the long-running Ollama
 * reads so Tomcat's request threads are released immediately.
 */
@RestController
@RequestMapping("/api/assistant")
@RequiredArgsConstructor
@Slf4j
public class AssistantController {

    private final AssistantService assistantService;
    private final ThreadService threadService;
    private final SourceCrossCheckService crossCheckService;
    private final TranslationService translationService;
    private final FollowUpService followUpService;

    /** Shared JSON mapper for the {@code sources} SSE payload. */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Dedicated executor so streaming chats don't steal Tomcat request
     * threads. Cached pool is fine - each chat lives only as long as the
     * model is generating tokens (seconds to ~1 min).
     */
    private final ExecutorService streamExecutor =
            Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "assistant-stream");
                t.setDaemon(true);
                return t;
            });

    /**
     * Streams the assistant's answer. The response is a stream of
     * {@code text/event-stream} events. Two event types:
     *
     * <pre>
     * event: token
     * data: &lt;partial text fragment&gt;
     *
     * event: done
     * data: ok
     * </pre>
     *
     * <p>Errors are surfaced as a final {@code error} event before the
     * emitter completes.
     */
    @PostMapping(value = "/chat", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter chat(@Valid @RequestBody ChatRequestDTO request) {
        // 5 min ceiling - covers cold-loaded Ollama models on slow laptops
        SseEmitter emitter = new SseEmitter(5L * 60_000L);

        // Single source of truth for "has this emitter already been
        // closed". Without it we were calling emitter.complete() twice
        // on client-disconnect races - once from onTimeout/onError, once
        // from our own done/error handler - and Tomcat throws
        // "ResponseBodyEmitter has already completed" the second time.
        AtomicBoolean closed = new AtomicBoolean(false);

        emitter.onTimeout(() -> {
            if (closed.compareAndSet(false, true)) {
                log.info("SSE timed out after 5 minutes, completing emitter");
                try { emitter.complete(); } catch (Exception ignored) {}
            }
        });
        emitter.onCompletion(() -> closed.set(true));
        emitter.onError(ex -> {
            if (closed.compareAndSet(false, true)) {
                log.warn("SSE error: {}", ex.getMessage());
                try { emitter.complete(); } catch (Exception ignored) {}
            }
        });

        List<OllamaClient.Message> history = new ArrayList<>();
        if (request.getHistory() != null) {
            for (ChatRequestDTO.HistoryTurn h : request.getHistory()) {
                if (h.getRole() != null && h.getContent() != null) {
                    history.add(new OllamaClient.Message(h.getRole(), h.getContent()));
                }
            }
        }

        // Thread-aware persistence: if the client attached a threadId, we
        // snapshot the user's question up-front and accumulate tokens into
        // a buffer so we can write the full answer + citations into the
        // thread once streaming finishes. Failure to persist never breaks
        // the stream - the transcript is a nice-to-have, not a contract.
        final String threadId = request.getThreadId();
        final boolean persist = threadId != null && !threadId.isBlank();
        if (persist) {
            try {
                threadService.appendUserMessage(threadId, request.getQuestion());
            } catch (Exception e) {
                log.warn("Could not persist user turn to thread {}: {}", threadId, e.getMessage());
            }
        }

        final StringBuilder answerBuffer = new StringBuilder();
        final AtomicReference<List<Citation>> capturedCitations =
                new AtomicReference<>(Collections.emptyList());
        // Heartbeat telemetry: every so often we log "still streaming,
        // N tokens so far, M ms since last token" so we can tell from
        // the log alone whether Ollama is actually producing or stuck.
        final AtomicInteger tokenCount = new AtomicInteger();
        final AtomicLong lastTokenAt = new AtomicLong(System.currentTimeMillis());
        final long startedAt = System.currentTimeMillis();

        streamExecutor.execute(() ->
                assistantService.streamAnswer(
                        request.getQuestion(),
                        history,
                        citations -> {
                            capturedCitations.set(citations == null ? Collections.emptyList() : citations);
                            try {
                                safeSend(emitter, closed, "sources", objectMapper.writeValueAsString(citations));
                            } catch (JsonProcessingException e) {
                                log.warn("Could not serialise citations: {}", e.getMessage());
                            }
                        },
                        token -> {
                            if (token != null) {
                                answerBuffer.append(token);
                            }
                            int n = tokenCount.incrementAndGet();
                            lastTokenAt.set(System.currentTimeMillis());
                            // Breadcrumbs without spamming: first token
                            // (time-to-first-token is the latency number
                            // that actually matters), then every 50.
                            if (n == 1) {
                                log.info("Assistant: first token after {} ms",
                                        System.currentTimeMillis() - startedAt);
                            } else if (n % 50 == 0) {
                                log.debug("Assistant: streamed {} tokens", n);
                            }
                            safeSend(emitter, closed, "token", token);
                        },
                        () -> {
                            log.info("Assistant: stream complete ({} tokens in {} ms)",
                                    tokenCount.get(), System.currentTimeMillis() - startedAt);
                            // Strip the trailing CONFIDENCE / NEEDS_MORE_SOURCES
                            // footer off the raw stream: the UI should only
                            // ever see prose, with the metadata arriving
                            // separately on the `meta` event below.
                            ParsedAnswer parsed = AssistantService.parseAnswerMetadata(
                                    answerBuffer.toString());
                            AnswerMetadata meta = parsed.metadata();
                            try {
                                safeSend(emitter, closed, "meta",
                                        objectMapper.writeValueAsString(Map.of(
                                                "confidence", meta.confidence().name(),
                                                "needsMoreSources", meta.needsMoreSources()
                                        )));
                            } catch (JsonProcessingException e) {
                                log.warn("Could not serialise answer metadata: {}", e.getMessage());
                            }
                            // Run the source cross-check against the
                            // citations we pulled for this answer. The
                            // service returns an empty list when the
                            // corpus is unanimous - we still emit the
                            // event so the UI can clear any stale
                            // warnings from a previous turn.
                            List<ConsistencyWarning> warnings = Collections.emptyList();
                            try {
                                List<Citation> cites = capturedCitations.get();
                                if (cites != null && !cites.isEmpty()) {
                                    List<SourceCrossCheckService.Passage> passages = new ArrayList<>(cites.size());
                                    for (Citation c : cites) {
                                        passages.add(new SourceCrossCheckService.Passage(
                                                c.index(), c.source(), c.sourceType(), c.snippet()));
                                    }
                                    warnings = crossCheckService.check(passages);
                                }
                            } catch (Exception e) {
                                log.warn("Cross-check failed: {}", e.getMessage());
                            }
                            String consistencyJson = null;
                            try {
                                consistencyJson = objectMapper.writeValueAsString(warnings);
                                safeSend(emitter, closed, "consistency", consistencyJson);
                            } catch (JsonProcessingException e) {
                                log.warn("Could not serialise consistency warnings: {}", e.getMessage());
                            }
                            if (persist) {
                                try {
                                    var savedMessage = threadService.appendAssistantMessage(
                                            threadId,
                                            parsed.visibleText(),
                                            capturedCitations.get(),
                                            meta);
                                    if (savedMessage != null && consistencyJson != null) {
                                        threadService.writeConsistency(
                                                savedMessage.getId(), consistencyJson);
                                    }
                                } catch (Exception e) {
                                    log.warn("Could not persist assistant turn to thread {}: {}",
                                            threadId, e.getMessage());
                                }
                            }
                            safeSend(emitter, closed, "done", "ok");
                            if (closed.compareAndSet(false, true)) {
                                try { emitter.complete(); } catch (Exception ignored) {}
                            }
                        },
                        err -> {
                            log.warn("Assistant: stream errored after {} tokens / {} ms: {}",
                                    tokenCount.get(), System.currentTimeMillis() - startedAt,
                                    err.getMessage());
                            safeSend(emitter, closed, "error",
                                    err.getMessage() == null ? "error" : err.getMessage());
                            if (closed.compareAndSet(false, true)) {
                                try { emitter.complete(); } catch (Exception ignored) {}
                            }
                        }
                )
        );

        return emitter;
    }

    /**
     * Offline translation endpoint. Body: {@code {"text": "...",
     * "targetLang": "TR"}}. Returns the translated text in a
     * {@code {"translated": "..."}} envelope. Falls back to the
     * original text on any Ollama error (never 5xx's the caller).
     */
    @PostMapping("/translate")
    public ResponseEntity<Map<String, String>> translate(@RequestBody Map<String, String> body) {
        String text = body == null ? null : body.get("text");
        String langRaw = body == null ? null : body.get("targetLang");
        if (text == null || text.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "text is required"));
        }
        if (langRaw == null || langRaw.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "targetLang is required"));
        }
        TranslationService.Language target;
        try {
            target = TranslationService.Language.valueOf(langRaw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "unsupported targetLang: " + langRaw
                            + " (supported: EN, TR, DE, FR, ES)"));
        }
        String translated = translationService.translate(text, target);
        return ResponseEntity.ok(Map.of("translated", translated));
    }

    /**
     * Produce 3 follow-up question suggestions for a Q&A pair. Body:
     * {@code {"question": "...", "answer": "..."}}. Empty list is a
     * legitimate response (model offline, parse miss), not an error.
     */
    @PostMapping("/suggest-followups")
    public ResponseEntity<Map<String, Object>> suggestFollowUps(@RequestBody Map<String, String> body) {
        String q = body == null ? null : body.get("question");
        String a = body == null ? null : body.get("answer");
        if (q == null || q.isBlank() || a == null || a.isBlank()) {
            return ResponseEntity.ok(Map.of("suggestions", List.of()));
        }
        List<String> suggestions = followUpService.suggest(q, a);
        return ResponseEntity.ok(Map.of("suggestions", suggestions));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        boolean ready = assistantService.isReady();
        return ResponseEntity.ok(Map.of(
                "status", ready ? "UP" : "DOWN",
                "service", "AssistantService",
                "knowledgeBaseSize", assistantService.knowledgeBaseSize()
        ));
    }

    /**
     * Push one SSE event, swallowing the exceptions that fire when the
     * client has already disconnected. The {@code closed} flag is flipped
     * so subsequent work (persistence, completion) knows not to touch
     * the emitter again.
     */
    private void safeSend(SseEmitter emitter, AtomicBoolean closed, String eventName, String data) {
        if (closed.get()) return;
        try {
            emitter.send(SseEmitter.event().name(eventName).data(data));
        } catch (IOException | IllegalStateException e) {
            // Client disconnected, or Tomcat already recycled the response.
            // Either way this emitter is dead - mark it so we stop trying.
            log.debug("SSE send failed ({}): {}", eventName, e.getMessage());
            closed.set(true);
        }
    }
}

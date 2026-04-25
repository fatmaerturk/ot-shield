package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.AlternativeDTO;
import com.safetech.otshield.dto.research.ResearchMessageDTO;
import com.safetech.otshield.dto.research.ResearchThreadDTO;
import com.safetech.otshield.model.research.ResearchMessage;
import com.safetech.otshield.model.research.ResearchThread;
import com.safetech.otshield.service.assistant.AlternativesService;
import com.safetech.otshield.service.assistant.AlternativesService.Alternative;
import com.safetech.otshield.service.research.ThreadService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST surface for the Research Studio "Threads" tab. Threads are read
 * heavily (list / open) and written occasionally (rename, delete). The
 * append operations happen indirectly from {@code AssistantController}
 * when a chat turn completes - this controller only exposes management
 * endpoints plus a {@code POST /} for the "New thread" button.
 */
@RestController
@RequestMapping("/api/research/threads")
@RequiredArgsConstructor
@Slf4j
public class ThreadController {

    private final ThreadService threadService;
    private final AlternativesService alternativesService;

    /** All threads, most recently active first. Honours {@code X-Bundle-Id}. */
    @GetMapping
    public ResponseEntity<List<ResearchThreadDTO>> list(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String scoped = (bundleId == null || bundleId.isBlank()) ? null : bundleId;
        List<ResearchThreadDTO> rows = threadService.listThreads(scoped)
                .stream().map(ResearchThreadDTO::from).toList();
        return ResponseEntity.ok(rows);
    }

    /** Single thread metadata (no messages) - fast enough for polling. */
    @GetMapping("/{threadId}")
    public ResponseEntity<ResearchThreadDTO> get(@PathVariable String threadId) {
        return threadService.getThread(threadId)
                .map(ResearchThreadDTO::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** Full transcript for a thread, oldest message first. */
    @GetMapping("/{threadId}/messages")
    public ResponseEntity<List<ResearchMessageDTO>> messages(@PathVariable String threadId) {
        List<ResearchMessageDTO> rows = threadService.listMessages(threadId)
                .stream().map(m -> ResearchMessageDTO.from(m, threadService, alternativesService))
                .toList();
        return ResponseEntity.ok(rows);
    }

    /**
     * Generate 2–3 contrarian alternative hypotheses for the given
     * assistant message. Synchronous — this call blocks for up to ~45s
     * (the underlying {@link AlternativesService} enforces its own
     * timeout). The parsed list is persisted onto the message so
     * subsequent GETs of the transcript surface it immediately, and
     * the user sees the same alternatives after a page reload.
     *
     * <p>Re-running the endpoint overwrites the stored list, which is
     * the behaviour researchers asked for: "give me another set".
     */
    @PostMapping("/{threadId}/messages/{messageId}/alternatives")
    public ResponseEntity<List<AlternativeDTO>> alternatives(
            @PathVariable String threadId,
            @PathVariable String messageId) {

        Optional<ResearchMessage> opt = threadService.getMessage(messageId);
        if (opt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        ResearchMessage msg = opt.get();
        if (!"assistant".equalsIgnoreCase(msg.getRole())) {
            // Guard against UI bugs that might ask for alternatives on a
            // user turn: that's nonsensical (the user's question doesn't
            // have a primary answer to disagree with).
            return ResponseEntity.badRequest().build();
        }
        if (!threadId.equals(msg.getThreadId())) {
            // Defensive: the message id should belong to the thread id
            // in the URL. If someone tampers with paths we 404.
            return ResponseEntity.notFound().build();
        }

        // Reconstruct the original question by walking backwards from
        // this assistant message to the nearest preceding user turn in
        // the same thread. If there's no user turn above it (rare, but
        // possible on imported threads) we fall back to empty string
        // and let the model infer from the primary answer alone.
        String question = findPrecedingUserQuestion(msg);
        List<Alternative> raw = alternativesService.generate(question, msg.getContent());
        String json = alternativesService.toJson(raw);
        threadService.writeAlternatives(messageId, json);

        List<AlternativeDTO> out = new ArrayList<>(raw.size());
        for (Alternative a : raw) out.add(AlternativeDTO.from(a));
        return ResponseEntity.ok(out);
    }

    /**
     * Walks the thread transcript up to - but not including - the
     * target assistant message and returns the most recent user turn
     * it finds. Returns an empty string when none exists.
     */
    private String findPrecedingUserQuestion(ResearchMessage target) {
        List<ResearchMessage> all = threadService.listMessages(target.getThreadId());
        String lastUser = "";
        for (ResearchMessage m : all) {
            if (m.getId().equals(target.getId())) break;
            if ("user".equalsIgnoreCase(m.getRole())) {
                lastUser = m.getContent() == null ? "" : m.getContent();
            }
        }
        return lastUser;
    }

    /**
     * Creates a new empty thread. The body can optionally carry a
     * {@code firstQuestion} to seed the title; most callers just pass
     * an empty JSON object and rename later.
     */
    @PostMapping
    public ResponseEntity<ResearchThreadDTO> create(
            @RequestBody(required = false) Map<String, String> body,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String firstQuestion = body == null ? "" : body.getOrDefault("firstQuestion", "");
        String bodyBundle = body == null ? null : body.get("bundleId");
        String scoped = firstNonBlank(bodyBundle, bundleId);
        ResearchThread thread = threadService.createThread(firstQuestion, scoped);
        return ResponseEntity.ok(ResearchThreadDTO.from(thread));
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    /** Rename a thread. Body: {@code {"title": "..."}}. */
    @PatchMapping("/{threadId}")
    public ResponseEntity<ResearchThreadDTO> rename(
            @PathVariable String threadId,
            @RequestBody Map<String, String> body) {
        String title = body == null ? null : body.get("title");
        return threadService.renameThread(threadId, title)
                .map(ResearchThreadDTO::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** Hard-delete a thread and all its messages. */
    @DeleteMapping("/{threadId}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String threadId) {
        threadService.deleteThread(threadId);
        return ResponseEntity.ok(Map.of("deleted", true, "id", threadId));
    }
}

package com.safetech.otshield.service.research;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.ExtractionJob;
import com.safetech.otshield.model.research.InventoryItem;
import com.safetech.otshield.model.research.InventoryItem.Kind;
import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.model.research.ResearchDocument.IngestStatus;
import com.safetech.otshield.model.research.ResearchDocumentChunk;
import com.safetech.otshield.repository.research.ExtractionJobRepository;
import com.safetech.otshield.repository.research.InventoryItemRepository;
import com.safetech.otshield.repository.research.ResearchDocumentChunkRepository;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import com.safetech.otshield.service.assistant.OllamaClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * LLM-driven "deep" inventory extractor. Complements the cheap
 * regex pass in {@link InventoryExtractor} by catching things like
 * "a USB-A port is available on the rear of the unit", or "the
 * update channel uses CoAP over DTLS" which regex doesn't pick up
 * reliably.
 *
 * <p>The design mirrors the async Summary generator:
 *
 * <ul>
 *   <li>The HTTP call starts the job, flips status to {@code GENERATING}
 *       and returns immediately.</li>
 *   <li>A background daemon thread builds a corpus slice, asks Ollama
 *       to emit a strict JSON list of items, parses defensively, and
 *       upserts the rows.</li>
 *   <li>The frontend polls the status endpoint every couple of seconds
 *       to observe {@code READY} or {@code FAILED}.</li>
 * </ul>
 *
 * <p>Parsing is deliberately forgiving: the model often wraps JSON in
 * markdown fences or prepends a preamble. We scan for the first JSON
 * array we can find and skip entries missing required fields. A
 * duplicate guard against {@code (kind, lowercased name)} means
 * re-running is safe.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InventoryDeepExtractor {

    private final ResearchDocumentRepository documentRepo;
    private final ResearchDocumentChunkRepository chunkRepo;
    private final InventoryItemRepository inventoryRepo;
    private final ExtractionJobRepository jobRepo;
    private final OllamaClient ollamaClient;
    private final ObjectMapper mapper;

    // Aggressive budget so the LLM returns quickly. Same sizing as
    // Summary; deep extract is best thought of as "second-pass
    // clean-up", not "read the entire corpus from scratch".
    private static final int MAX_CHARS_PER_DOC = 400;
    private static final int MAX_TOTAL_CORPUS_CHARS = 2000;
    private static final int MAX_CHUNKS_PER_DOC = 1;
    private static final int MAX_DOCS = 6;

    private static final String SYSTEM_PROMPT = """
            You extract structured inventory from technical excerpts of an
            industrial product. Output STRICT JSON only, no prose, no
            markdown fences.

            Return an array of objects. Each object has:
            - "kind": one of "PORT", "PROTOCOL", "SERVICE", "COMPONENT"
            - "name": short label (e.g. "Port 102/TCP", "S7Comm", "Web UI", "STM32F407")
            - "reference": optional short free text (e.g. "U4", "eth0")

            Rules:
            - Only use facts grounded in the provided excerpts.
            - Do not invent CVE numbers, model numbers, or ports that are
              not in the excerpts.
            - If the excerpts contain nothing extractable, return [].
            - No preamble, no trailing text, just the JSON array.
            """;

    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "inventory-deep-extract");
        t.setDaemon(true);
        return t;
    });

    // ---- Public entry point -------------------------------------------

    @Transactional
    public ExtractionJob start(String bundleId) {
        LocalDateTime now = LocalDateTime.now();
        ExtractionJob job = jobRepo.findById(bundleId).orElse(
                ExtractionJob.builder().bundleId(bundleId).build());

        if ("GENERATING".equals(job.getStatus())) {
            log.info("Deep extract ignored - already in flight for bundle={}", bundleId);
            return job;
        }

        job.setBundleId(bundleId);
        job.setStatus("GENERATING");
        job.setMessage(null);
        job.setItemsCreated(0);
        job.setStartedAt(now);
        job.setFinishedAt(null);
        ExtractionJob queued = jobRepo.save(job);

        worker.submit(() -> runDeep(bundleId));
        log.info("Deep extract queued for bundle={}", bundleId);
        return queued;
    }

    public Optional<ExtractionJob> status(String bundleId) {
        return jobRepo.findById(bundleId);
    }

    // ---- Background worker --------------------------------------------

    @Transactional
    public void runDeep(String bundleId) {
        long t0 = System.currentTimeMillis();
        ExtractionJob job = jobRepo.findById(bundleId).orElse(
                ExtractionJob.builder().bundleId(bundleId).status("GENERATING").build());

        List<ResearchDocument> allReady = documentRepo.findByBundleIdOrderByUploadedAtDesc(bundleId)
                .stream().filter(d -> d.getStatus() == IngestStatus.READY).toList();
        List<ResearchDocument> docs = allReady.size() <= MAX_DOCS
                ? allReady : allReady.subList(0, MAX_DOCS);

        if (docs.isEmpty()) {
            finish(job, "READY", "No READY documents to deep-extract from.", 0);
            return;
        }

        String corpus = buildCorpus(docs);
        String userPrompt = "Technical excerpts from " + docs.size()
                + " source document(s). Return extracted inventory as JSON.\n\n" + corpus;

        log.info("Deep extract: bundle={} across {} docs, {} chars of corpus",
                bundleId, docs.size(), corpus.length());

        StringBuilder out = new StringBuilder();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        long ollamaStart = System.currentTimeMillis();

        ollamaClient.streamChat(
                List.of(
                        new OllamaClient.Message("system", SYSTEM_PROMPT),
                        new OllamaClient.Message("user", userPrompt)
                ),
                out::append,
                () -> log.info("Deep extract: ollama done for bundle={} in {} ms",
                        bundleId, System.currentTimeMillis() - ollamaStart),
                err -> {
                    log.warn("Deep extract ollama error for bundle={} in {} ms: {}",
                            bundleId, System.currentTimeMillis() - ollamaStart, err.getMessage());
                    failure.set(err);
                }
        );

        if (failure.get() != null) {
            finish(job, "FAILED", "Ollama error: " + failure.get().getMessage(), 0);
            return;
        }

        String raw = out.toString();
        JsonNode arr = extractJsonArray(raw);
        if (arr == null || !arr.isArray()) {
            finish(job, "FAILED",
                    "Model did not return a parseable JSON array. Try the regex extract instead.", 0);
            log.warn("Deep extract: non-JSON response for bundle={}: {}",
                    bundleId, raw.length() > 160 ? raw.substring(0, 160) + "..." : raw);
            return;
        }

        // Existing dedupe set - same policy as the regex extractor
        Set<String> existingKeys = new HashSet<>();
        for (InventoryItem it : inventoryRepo.findByBundleIdOrderByUpdatedAtDesc(bundleId)) {
            existingKeys.add(dedupeKey(it.getKind(), it.getName()));
        }

        LocalDateTime now = LocalDateTime.now();
        int created = 0;
        for (JsonNode entry : arr) {
            if (!entry.isObject()) continue;
            String rawKind = entry.path("kind").asText(null);
            String name = entry.path("name").asText(null);
            String reference = entry.path("reference").asText(null);
            if (rawKind == null || name == null || name.isBlank()) continue;

            Kind kind = safeKind(rawKind);
            if (kind == null) continue;

            String key = dedupeKey(kind, name);
            if (existingKeys.contains(key)) continue;

            inventoryRepo.save(InventoryItem.builder()
                    .id(UUID.randomUUID().toString())
                    .bundleId(bundleId)
                    .kind(kind)
                    .name(name.trim())
                    .reference(reference == null || reference.isBlank() ? null : reference.trim())
                    .source("llm:deep-extract")
                    .tags("auto,llm")
                    .createdAt(now)
                    .updatedAt(now)
                    .build());
            existingKeys.add(key);
            created++;
        }

        finish(job, "READY",
                "Deep extract added " + created + " new item(s).",
                created);

        log.info("Deep extract: bundle={} wrote {} items in {} ms",
                bundleId, created, System.currentTimeMillis() - t0);
    }

    // ---- Helpers ------------------------------------------------------

    private void finish(ExtractionJob job, String status, String message, int items) {
        job.setStatus(status);
        job.setMessage(message);
        job.setItemsCreated(items);
        job.setFinishedAt(LocalDateTime.now());
        jobRepo.save(job);
    }

    private String buildCorpus(List<ResearchDocument> docs) {
        StringBuilder sb = new StringBuilder();
        int index = 1;
        int total = 0;
        for (ResearchDocument doc : docs) {
            if (total >= MAX_TOTAL_CORPUS_CHARS) break;
            List<ResearchDocumentChunk> chunks =
                    chunkRepo.findByDocumentIdOrderByOrdinalAsc(doc.getId());
            int perDocUsed = 0;
            int takenFromDoc = 0;
            for (ResearchDocumentChunk c : chunks) {
                if (takenFromDoc >= MAX_CHUNKS_PER_DOC) break;
                if (perDocUsed >= MAX_CHARS_PER_DOC) break;
                if (total >= MAX_TOTAL_CORPUS_CHARS) break;
                String compact = c.getText() == null ? "" :
                        c.getText().replaceAll("\\s+", " ").trim();
                if (compact.isBlank()) continue;
                int room = Math.min(MAX_CHARS_PER_DOC - perDocUsed,
                                    MAX_TOTAL_CORPUS_CHARS - total);
                if (compact.length() > room) compact = compact.substring(0, Math.max(0, room - 3)) + "...";
                sb.append("\n[").append(index++).append("] ")
                  .append(doc.getFileName()).append('\n')
                  .append(compact).append('\n');
                perDocUsed += compact.length();
                takenFromDoc++;
                total += compact.length();
            }
        }
        return sb.toString();
    }

    /**
     * Forgiving JSON array extractor: finds the first '[' that opens a
     * balanced array in the raw model output and returns that slice
     * parsed, or null. Tolerates markdown fences, preambles and
     * trailing prose.
     */
    private JsonNode extractJsonArray(String raw) {
        if (raw == null) return null;
        int start = raw.indexOf('[');
        if (start < 0) return null;
        int depth = 0;
        int end = -1;
        boolean inString = false;
        boolean escape = false;
        for (int i = start; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (inString) {
                if (escape) { escape = false; }
                else if (ch == '\\') { escape = true; }
                else if (ch == '"') { inString = false; }
                continue;
            }
            if (ch == '"') { inString = true; continue; }
            if (ch == '[') depth++;
            else if (ch == ']') {
                depth--;
                if (depth == 0) { end = i; break; }
            }
        }
        if (end < 0) return null;
        String slice = raw.substring(start, end + 1);
        try {
            return mapper.readTree(slice);
        } catch (Exception e) {
            return null;
        }
    }

    private static Kind safeKind(String raw) {
        if (raw == null) return null;
        try { return Kind.valueOf(raw.trim().toUpperCase(Locale.ROOT)); }
        catch (Exception e) { return null; }
    }

    private static String dedupeKey(Kind kind, String name) {
        String n = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
        return kind.name() + "||" + n;
    }
}

package com.safetech.otshield.service.research;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.BundleSummary;
import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.model.research.ResearchDocument.IngestStatus;
import com.safetech.otshield.model.research.ResearchDocumentChunk;
import com.safetech.otshield.repository.research.BundleSummaryRepository;
import com.safetech.otshield.repository.research.ResearchDocumentChunkRepository;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import com.safetech.otshield.service.assistant.AssistantProperties;
import com.safetech.otshield.service.assistant.OllamaClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Generates and persists the per-bundle technical summary that backs
 * the Summary tab. HMGCC requirement: "Generate a clear technical
 * summary of the product and its individual components."
 *
 * <p>Approach: gather all {@code READY} documents in the bundle, pull
 * a fixed-size "corpus slice" (the first handful of chunks from each),
 * compose a prompt that names each source document, and ask the chat
 * model to produce a structured markdown summary - identity, hardware
 * interfaces, protocols, notable configuration, open questions. The
 * result is cached in {@link BundleSummary}; regeneration is explicit
 * so the researcher controls when inference runs.
 *
 * <p>Offline-first per the HMGCC constraint: uses the local Ollama
 * chat model, no external calls.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SummaryService {

    private final BundleSummaryRepository summaryRepo;
    private final ResearchDocumentRepository documentRepo;
    private final ResearchDocumentChunkRepository chunkRepo;
    private final OllamaClient ollamaClient;
    private final AssistantProperties props;
    private final ObjectMapper objectMapper;

    /**
     * Single-thread executor. We only want one summary in flight per
     * JVM so parallel requests queue instead of hammering Ollama; each
     * task blocks its slot until the model finishes. A cached pool
     * would be worse here - two concurrent 1B inferences on a CPU-only
     * host thrash the cache and take longer than running them in series.
     */
    private final ExecutorService generator = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "summary-generator");
        t.setDaemon(true);
        return t;
    });

    // ---- Budget (tuned for CPU-only Ollama on modest laptops) ----------
    // The generator is the slowest thing in the whole product; cutting
    // the prompt size roughly halves per-token latency, and fewer
    // generated tokens (via num_predict in OllamaClient) shaves minutes
    // off the overall runtime. These numbers still leave enough context
    // for a useful 5-section summary of a typical 40-page PDF.

    // Aggressive budget - inference latency on CPU-only hosts dominates
    // everything else in the UX, so we trade some summary richness for
    // a generator that actually finishes on a laptop. A 40-page vendor
    // manual still leaves plenty for the model to ground against.

    /** Cap per-document excerpt so the prompt fits comfortably inside num_ctx. */
    private static final int MAX_CHARS_PER_DOC = 400;

    /** Cap total corpus slice so a 20-doc bundle doesn't blow the window. */
    private static final int MAX_TOTAL_CORPUS_CHARS = 2000;

    /** Maximum chunks per document used to build the slice. */
    private static final int MAX_CHUNKS_PER_DOC = 1;

    /** Hard cap on source documents fed to the generator per run. */
    private static final int MAX_DOCS_IN_PROMPT = 6;

    // Short system prompt: every token in here is re-processed on every
    // call, so verbosity costs us CPU. Three sections keeps the output
    // generation short too.
    private static final String SYSTEM_PROMPT = """
            You are OTShield Research Analyst. Summarise the provided
            excerpts about one industrial product. Output short markdown
            with exactly these three sections:

            ## Overview
            One or two sentences: what it is, who makes it.

            ## Interfaces & protocols
            Bullets for physical ports, network interfaces, protocols,
            default port numbers. Cite sources inline with [1], [2] etc.

            ## Security notes
            Bullets for default credentials, services on by default,
            firmware update mechanism. Cite sources.

            Rules: bullets not paragraphs; only facts from the excerpts;
            no invented CVE numbers; no preamble.
            """;

    // ---- Reads ---------------------------------------------------------

    public Optional<BundleSummary> get(String bundleId) {
        return summaryRepo.findById(bundleId);
    }

    // ---- Manual edit ---------------------------------------------------

    /**
     * Overwrite the cached summary with whatever the researcher typed.
     * Used for the "Edit" mode of the Summary tab - the generator
     * stays frozen until explicitly regenerated.
     */
    @Transactional
    public BundleSummary saveEdit(String bundleId, String text, String editedBy) {
        LocalDateTime now = LocalDateTime.now();
        BundleSummary s = summaryRepo.findById(bundleId).orElse(
                BundleSummary.builder().bundleId(bundleId).build());
        s.setBundleId(bundleId);
        s.setText(text == null ? "" : text);
        s.setEditedAt(now);
        s.setEditedBy(editedBy);
        // Manual edits are terminal: the text is authoritative so
        // whatever was there (even a stale GENERATING from a crashed
        // worker) gets cleared.
        s.setStatus("READY");
        return summaryRepo.save(s);
    }

    // ---- Generation ----------------------------------------------------

    /**
     * Non-blocking regenerate. Flips the row to {@code GENERATING} and
     * returns immediately; a background worker runs the LLM and
     * eventually flips the row to {@code READY} or {@code FAILED}. The
     * frontend polls {@link #get} every few seconds to pick up the new
     * state.
     *
     * <p>If a generation is already in flight for this bundle the call
     * is a no-op: we don't want two workers writing to the same row.
     */
    @Transactional
    public BundleSummary regenerate(String bundleId) {
        LocalDateTime now = LocalDateTime.now();
        BundleSummary s = summaryRepo.findById(bundleId).orElse(
                BundleSummary.builder().bundleId(bundleId).build());

        if ("GENERATING".equals(s.getStatus())) {
            log.info("Summary: regenerate for bundle={} ignored - already in flight", bundleId);
            return s;
        }

        s.setBundleId(bundleId);
        s.setStatus("GENERATING");
        s.setGeneratedAt(now);
        s.setEditedAt(null);
        s.setEditedBy(null);
        // Keep the previous text visible while we work so the UI doesn't
        // flash empty - the status flag is enough to tell the frontend
        // the displayed text is stale.
        BundleSummary queued = summaryRepo.save(s);

        generator.submit(() -> runGeneration(bundleId));
        log.info("Summary: queued generation for bundle={}", bundleId);
        return queued;
    }

    /**
     * Background worker. Runs outside the request thread and writes the
     * final state in its own transaction so failures don't leak into
     * the HTTP response the controller already returned.
     */
    @Transactional
    public void runGeneration(String bundleId) {
        long t0 = System.currentTimeMillis();
        LocalDateTime now = LocalDateTime.now();

        List<ResearchDocument> allReady = documentRepo.findByBundleIdOrderByUploadedAtDesc(bundleId)
                .stream()
                .filter(d -> d.getStatus() == IngestStatus.READY)
                .toList();
        // Cap the number of source docs so a research bundle with 40
        // PDFs doesn't compose a 30-minute prompt. We take the most
        // recently uploaded ones - the rest are still in the corpus
        // for RAG retrieval, they just don't feed the summary.
        List<ResearchDocument> docs = allReady.size() <= MAX_DOCS_IN_PROMPT
                ? allReady
                : allReady.subList(0, MAX_DOCS_IN_PROMPT);

        BundleSummary s = summaryRepo.findById(bundleId).orElse(
                BundleSummary.builder().bundleId(bundleId).build());
        s.setBundleId(bundleId);
        s.setModel(props.getChatModel());

        if (docs.isEmpty()) {
            s.setText("""
                    _No READY documents in this bundle yet._

                    Upload vendor manuals, datasheets or forum excerpts in
                    the Library tab, wait for them to finish ingesting, then
                    come back and hit **Regenerate**.
                    """);
            s.setSourceDocIdsJson("[]");
            s.setPromptTokens(0);
            s.setStatus("READY");
            s.setGeneratedAt(now);
            summaryRepo.save(s);
            return;
        }

        CorpusSlice slice = buildCorpusSlice(docs);
        String userPrompt = "Technical excerpts from " + docs.size()
                + " source document(s). Use the bracketed indices when citing.\n\n"
                + slice.passages();

        log.info("Summary: generating for bundle={} across {} docs ({} chars of corpus, {} chars of user prompt)",
                bundleId, docs.size(), slice.passages().length(), userPrompt.length());

        StringBuilder out = new StringBuilder();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        long ollamaStart = System.currentTimeMillis();

        // OllamaClient.streamChat is synchronous inside the calling
        // thread. Because we're already on the generator executor,
        // blocking here is exactly what we want - we just shouldn't
        // block a Tomcat worker.
        ollamaClient.streamChat(
                List.of(
                        new OllamaClient.Message("system", SYSTEM_PROMPT),
                        new OllamaClient.Message("user", userPrompt)
                ),
                out::append,
                () -> log.info("Summary: ollama stream done for bundle={} in {} ms, {} chars produced",
                        bundleId, System.currentTimeMillis() - ollamaStart, out.length()),
                err -> {
                    log.warn("Summary: ollama stream error for bundle={} after {} ms: {}",
                            bundleId, System.currentTimeMillis() - ollamaStart, err.getMessage());
                    failure.set(err);
                }
        );

        s.setPromptTokens(userPrompt.length() / 4);
        s.setGeneratedAt(now);
        s.setSourceDocIdsJson(toJson(slice.docIds()));

        if (failure.get() != null) {
            log.warn("Summary generation failed for bundle {}: {}",
                    bundleId, failure.get().getMessage());
            s.setText("_Summary generation failed:_ **" + failure.get().getMessage()
                    + "**\n\nCheck that Ollama is running and the chat model is pulled, "
                    + "then try again.");
            s.setStatus("FAILED");
        } else {
            String answer = out.toString().trim();
            if (answer.isEmpty()) {
                s.setText("_Generator returned an empty response._ Try again.");
                s.setStatus("FAILED");
            } else {
                s.setText(answer);
                s.setStatus("READY");
            }
        }
        summaryRepo.save(s);
        log.info("Summary: bundle={} status={} in {} ms",
                bundleId, s.getStatus(), System.currentTimeMillis() - t0);
    }

    // ---- Helpers -------------------------------------------------------

    /** Corpus slice paired with the list of doc IDs that went into it. */
    private record CorpusSlice(String passages, List<String> docIds) {}

    /**
     * Compose a prompt-ready snippet of the bundle's corpus: for each
     * document grab its first few chunks, trim, and number them
     * globally so the LLM can cite them with [1], [2]...
     */
    private CorpusSlice buildCorpusSlice(List<ResearchDocument> docs) {
        StringBuilder sb = new StringBuilder();
        List<String> usedDocIds = new ArrayList<>();
        int index = 1;
        int total = 0;

        for (ResearchDocument doc : docs) {
            if (total >= MAX_TOTAL_CORPUS_CHARS) break;
            List<ResearchDocumentChunk> chunks =
                    chunkRepo.findByDocumentIdOrderByOrdinalAsc(doc.getId());
            if (chunks.isEmpty()) continue;

            usedDocIds.add(doc.getId());
            int perDocUsed = 0;
            int takenFromDoc = 0;
            for (ResearchDocumentChunk c : chunks) {
                if (takenFromDoc >= MAX_CHUNKS_PER_DOC) break;
                if (perDocUsed >= MAX_CHARS_PER_DOC) break;
                if (total >= MAX_TOTAL_CORPUS_CHARS) break;

                String compact = c.getText() == null ? "" : c.getText().replaceAll("\\s+", " ").trim();
                if (compact.isBlank()) continue;

                int perDocRemaining = MAX_CHARS_PER_DOC - perDocUsed;
                int totalRemaining = MAX_TOTAL_CORPUS_CHARS - total;
                int room = Math.min(perDocRemaining, totalRemaining);
                if (compact.length() > room) {
                    compact = compact.substring(0, Math.max(0, room - 3)) + "...";
                }

                sb.append("\n[").append(index++).append("] ")
                  .append(doc.getFileName());
                if (c.getPageNumber() != null) {
                    sb.append(" (p.").append(c.getPageNumber()).append(")");
                }
                sb.append('\n').append(compact).append('\n');

                perDocUsed += compact.length();
                takenFromDoc += 1;
                total += compact.length();
            }
        }

        return new CorpusSlice(sb.toString(), usedDocIds);
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "[]";
        }
    }
}

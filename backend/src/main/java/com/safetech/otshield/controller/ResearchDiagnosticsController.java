package com.safetech.otshield.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import com.safetech.otshield.service.assistant.AssistantProperties;
import com.safetech.otshield.service.assistant.EmbeddingService;
import com.safetech.otshield.service.assistant.OllamaClient;
import com.safetech.otshield.service.assistant.VectorStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Operator-facing diagnostics for the Research Studio / RAG pipeline.
 *
 * <p>One endpoint, one purpose: when a document is stuck on {@code UPLOADED}
 * or the assistant is refusing to cite something that should be in the
 * corpus, hitting {@code /api/research/diagnostics} tells you in a single
 * page exactly where the pipeline is broken - Ollama reachable? Models
 * pulled? Embedding actually returning a vector? Vector store populated?
 * Which document is in which status with what error message?
 *
 * <p>This is deliberately not polished UI - it's a text blob meant to be
 * read by a developer or support engineer in five seconds to triage.
 */
@RestController
@RequestMapping("/api/research/diagnostics")
@RequiredArgsConstructor
@Slf4j
public class ResearchDiagnosticsController {

    private final AssistantProperties props;
    private final OllamaClient ollamaClient;
    private final EmbeddingService embeddingService;
    private final VectorStore vectorStore;
    private final ResearchDocumentRepository documentRepository;
    private final ObjectMapper mapper = new ObjectMapper();

    @GetMapping
    public ResponseEntity<Map<String, Object>> diagnose() {
        Map<String, Object> out = new LinkedHashMap<>();

        // 1. Ollama reachability
        Map<String, Object> ollama = new LinkedHashMap<>();
        ollama.put("baseUrl", props.getBaseUrl());
        ollama.put("chatModel", props.getChatModel());
        ollama.put("embeddingModel", props.getEmbeddingModel());
        ollama.put("ping", ollamaClient.ping());

        // 2. Model list from /api/tags
        List<String> availableModels = new ArrayList<>();
        String tagsError = null;
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(props.getBaseUrl() + "/api/tags"))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> resp = HttpClient.newHttpClient()
                    .send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                JsonNode root = mapper.readTree(resp.body());
                JsonNode models = root.get("models");
                if (models != null && models.isArray()) {
                    for (JsonNode m : models) {
                        JsonNode name = m.get("name");
                        if (name != null) availableModels.add(name.asText());
                    }
                }
            } else {
                tagsError = "HTTP " + resp.statusCode();
            }
        } catch (Exception e) {
            tagsError = e.getMessage();
        }
        ollama.put("availableModels", availableModels);
        if (tagsError != null) ollama.put("tagsError", tagsError);
        ollama.put("chatModelInstalled", matchesAnyModel(availableModels, props.getChatModel()));
        ollama.put("embeddingModelInstalled", matchesAnyModel(availableModels, props.getEmbeddingModel()));

        // 3. Embedding smoke test - if this fails, ingest can never finish.
        Map<String, Object> embedCheck = new LinkedHashMap<>();
        try {
            long t0 = System.currentTimeMillis();
            float[] vec = embeddingService.embed("OTShield diagnostics self-test");
            embedCheck.put("ok", true);
            embedCheck.put("dimensions", vec.length);
            embedCheck.put("latencyMs", System.currentTimeMillis() - t0);
            embedCheck.put("firstThree", new float[]{
                    vec.length > 0 ? vec[0] : 0f,
                    vec.length > 1 ? vec[1] : 0f,
                    vec.length > 2 ? vec[2] : 0f,
            });
        } catch (Exception e) {
            embedCheck.put("ok", false);
            embedCheck.put("error", e.getMessage());
        }

        // 4. Vector store state
        Map<String, Object> vs = new LinkedHashMap<>();
        vs.put("chunks", vectorStore.size());

        // 5. Document roll-up (last 20, most recent first)
        List<Map<String, Object>> docs = new ArrayList<>();
        for (ResearchDocument d : documentRepository.findAllByOrderByUploadedAtDesc()) {
            if (docs.size() >= 20) break;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", d.getId());
            row.put("fileName", d.getFileName());
            row.put("status", d.getStatus() == null ? "null" : d.getStatus().name());
            row.put("chunkCount", d.getChunkCount());
            row.put("uploadedAt", d.getUploadedAt());
            row.put("ingestedAt", d.getIngestedAt());
            row.put("errorMessage", d.getErrorMessage());
            docs.add(row);
        }

        out.put("ollama", ollama);
        out.put("embeddingSmokeTest", embedCheck);
        out.put("vectorStore", vs);
        out.put("documents", docs);
        out.put("verdict", verdict(ollama, embedCheck, docs));
        return ResponseEntity.ok(out);
    }

    /**
     * Ollama reports model tags with the full qualified name, e.g.
     * {@code llama3.2:3b-instruct-q4_K_M}. We accept a prefix match on the
     * colon so {@code nomic-embed-text} matches {@code nomic-embed-text:latest}.
     */
    private static boolean matchesAnyModel(List<String> available, String wanted) {
        if (wanted == null) return false;
        String base = wanted.contains(":") ? wanted.substring(0, wanted.indexOf(':')) : wanted;
        for (String m : available) {
            if (m.equals(wanted)) return true;
            String mBase = m.contains(":") ? m.substring(0, m.indexOf(':')) : m;
            if (mBase.equals(base)) return true;
        }
        return false;
    }

    private static String verdict(Map<String, Object> ollama,
                                  Map<String, Object> embedCheck,
                                  List<Map<String, Object>> docs) {
        if (!Boolean.TRUE.equals(ollama.get("ping"))) {
            return "Ollama is not reachable at " + ollama.get("baseUrl")
                    + " - start it with `ollama serve`.";
        }
        if (!Boolean.TRUE.equals(ollama.get("embeddingModelInstalled"))) {
            return "Embedding model not installed - run `ollama pull " + ollama.get("embeddingModel") + "`.";
        }
        if (!Boolean.TRUE.equals(ollama.get("chatModelInstalled"))) {
            return "Chat model not installed - run `ollama pull " + ollama.get("chatModel") + "`.";
        }
        if (!Boolean.TRUE.equals(embedCheck.get("ok"))) {
            return "Embedding call failed: " + embedCheck.get("error");
        }
        long stuck = docs.stream()
                .filter(d -> {
                    String s = String.valueOf(d.get("status"));
                    return "UPLOADED".equals(s) || "PROCESSING".equals(s) || "FAILED".equals(s);
                })
                .count();
        if (stuck > 0) {
            return stuck + " document(s) not READY - see `errorMessage` per row and use the Retry button.";
        }
        return "All systems healthy.";
    }
}

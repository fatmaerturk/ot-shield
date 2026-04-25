package com.safetech.otshield.service.assistant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;

/**
 * Thin wrapper over the local Ollama HTTP API.
 *
 * <p>Uses the JDK's built-in {@link HttpClient} so we don't drag in WebFlux
 * just for two endpoints. Ollama's streaming chat returns NDJSON (one JSON
 * object per line), which we parse line-by-line and push into the caller's
 * consumer. For embeddings we use the one-shot {@code /api/embeddings}
 * endpoint which returns a single JSON body.
 *
 * <p>This class is intentionally dumb about prompts - higher level services
 * (AssistantService) build the message list and decide what to send.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OllamaClient {

    private final AssistantProperties props;
    private final ObjectMapper mapper = new ObjectMapper();

    private HttpClient httpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Represents one chat turn. Role must be "system", "user" or "assistant".
     */
    public record Message(String role, String content) {}

    /**
     * Streams a chat completion. Each partial token that Ollama emits is
     * pushed to {@code onToken}. When the stream ends (either because Ollama
     * set {@code done:true} or the socket closed), {@code onComplete} fires.
     * Any error is routed through {@code onError} - the method does not
     * throw synchronously.
     *
     * <p>Runs entirely on the calling thread - callers typically invoke this
     * from an async executor (SseEmitter dispatch thread).
     */
    public void streamChat(List<Message> messages,
                           Consumer<String> onToken,
                           Runnable onComplete,
                           Consumer<Throwable> onError) {
        try {
            ObjectNode body = mapper.createObjectNode();
            body.put("model", props.getChatModel());
            body.put("stream", true);
            ArrayNode msgs = body.putArray("messages");
            for (Message m : messages) {
                ObjectNode o = msgs.addObject();
                o.put("role", m.role());
                o.put("content", m.content());
            }
            // Keep temperature modest so the assistant sticks to the
            // retrieved context instead of hallucinating about OT details.
            //
            // Resource budget: num_thread pins CPU usage (0 = Ollama
            // default = all cores), num_ctx caps context window (smaller
            // is faster and uses less RAM), num_predict caps answer
            // length so a runaway generation can't chew the CPU.
            ObjectNode options = body.putObject("options");
            options.put("temperature", 0.3);
            options.put("num_ctx", props.getNumCtx());
            if (props.getNumThread() > 0) {
                options.put("num_thread", props.getNumThread());
            }
            options.put("num_predict", props.getNumPredict());

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(props.getBaseUrl() + "/api/chat"))
                    .timeout(Duration.ofSeconds(props.getTimeoutSeconds()))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();

            HttpResponse<java.io.InputStream> resp = httpClient()
                    .send(req, HttpResponse.BodyHandlers.ofInputStream());

            if (resp.statusCode() / 100 != 2) {
                String msg = "Ollama chat returned HTTP " + resp.statusCode();
                log.warn(msg);
                onError.accept(new IllegalStateException(msg));
                return;
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resp.body(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isBlank()) continue;
                    try {
                        JsonNode node = mapper.readTree(line);
                        JsonNode message = node.get("message");
                        if (message != null && message.has("content")) {
                            String token = message.get("content").asText();
                            if (!token.isEmpty()) {
                                onToken.accept(token);
                            }
                        }
                        if (node.has("done") && node.get("done").asBoolean()) {
                            break;
                        }
                    } catch (Exception parseEx) {
                        log.debug("Skipping malformed Ollama line: {}", line);
                    }
                }
            }
            onComplete.run();
        } catch (Exception e) {
            log.error("Ollama streamChat failed", e);
            onError.accept(e);
        }
    }

    /**
     * One-shot embedding. Returns the vector as a {@code float[]} - we use
     * float, not double, because nomic-embed-text already quantises to
     * roughly 4-decimal precision and halving memory is worth it when the
     * vector store is in-process.
     */
    public float[] embed(String text) {
        try {
            ObjectNode body = mapper.createObjectNode();
            body.put("model", props.getEmbeddingModel());
            body.put("prompt", text);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(props.getBaseUrl() + "/api/embeddings"))
                    .timeout(Duration.ofSeconds(props.getTimeoutSeconds()))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();

            HttpResponse<String> resp = httpClient()
                    .send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (resp.statusCode() / 100 != 2) {
                throw new IllegalStateException(
                        "Ollama embeddings HTTP " + resp.statusCode() + ": " + resp.body());
            }
            JsonNode root = mapper.readTree(resp.body());
            JsonNode arr = root.get("embedding");
            if (arr == null || !arr.isArray()) {
                throw new IllegalStateException("Ollama response missing 'embedding' array");
            }
            float[] out = new float[arr.size()];
            for (int i = 0; i < arr.size(); i++) {
                out[i] = (float) arr.get(i).asDouble();
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException("Failed to embed text via Ollama", e);
        }
    }

    /**
     * Quick health check - used by the controller's /health endpoint to let
     * the UI decide whether to show "assistant unavailable" before the user
     * types anything.
     */
    public boolean ping() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(props.getBaseUrl() + "/api/tags"))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> resp = httpClient()
                    .send(req, HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200;
        } catch (Exception e) {
            log.debug("Ollama ping failed: {}", e.getMessage());
            return false;
        }
    }
}

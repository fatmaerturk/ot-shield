package com.safetech.otshield.service.assistant;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration for the OTShield AI assistant. Values are sourced from
 * application.properties under the {@code ollama.*} prefix so we can point
 * Ollama at a different host (or swap models) without code changes.
 *
 * <pre>
 * ollama.base-url        http://localhost:11434
 * ollama.chat-model      llama3.2:3b-instruct-q4_K_M
 * ollama.embedding-model nomic-embed-text
 * ollama.timeout-seconds 120
 * </pre>
 */
@Data
@Component
@ConfigurationProperties(prefix = "ollama")
public class AssistantProperties {

    /** Base URL of the local Ollama runtime. */
    private String baseUrl = "http://localhost:11434";

    /** Chat model tag - must already be pulled locally. */
    private String chatModel = "llama3.2:3b-instruct-q4_K_M";

    /** Embedding model tag - must already be pulled locally. */
    private String embeddingModel = "nomic-embed-text";

    /**
     * Socket read timeout for streaming chat responses.
     *
     * <p>Ollama's first request after boot has to load the model into
     * RAM - on a 3B q4 quant that's routinely 30-60s of dead air before
     * the first token streams. With a 6-passage RAG context on top, the
     * very first user question in a fresh session can push past two
     * minutes on modest hardware. We give it five to avoid spurious
     * "chat timed out" errors that resolve themselves on the second
     * try; subsequent requests reuse the hot model and finish quickly.
     */
    private int timeoutSeconds = 300;

    /**
     * If true, fire a trivial chat request at startup so Ollama loads
     * the model into memory before the first user question arrives.
     * Adds ~30-60s to backend startup on a cold host but prevents the
     * very first in-app query from timing out while the model warms up.
     */
    private boolean warmupOnStartup = true;

    /**
     * CPU threads Ollama is allowed to spin up per inference. Default
     * of 0 means "let Ollama decide" which on most laptops means all
     * physical cores - great for raw throughput, terrible for the host
     * staying responsive. Pin this to 4-8 on modest machines. On an
     * 8-core laptop, 6 is a decent compromise between speed and a
     * still-usable desktop.
     */
    private int numThread = 0;

    /**
     * Context window passed to the model. Smaller is faster and uses
     * less RAM; too small truncates the system prompt + RAG passages
     * and silently starves the answer. 2048 fits our RAG prompt with
     * room to spare.
     */
    private int numCtx = 2048;

    /**
     * Hard cap on generated tokens. Prevents runaway generations from
     * locking the CPU for minutes. 512 tokens is about 350 English
     * words - more than enough for a cited technical answer.
     */
    private int numPredict = 512;

    /** How many top-k chunks RAG should inject into the prompt. */
    private int retrievalTopK = 6;

    /**
     * Minimum cosine similarity for a chunk to be considered relevant.
     * With nomic-embed-text, domain-specific but paraphrased questions
     * often score in the 0.20-0.35 range; a stricter cut-off silently
     * starves the copilot of context. 0.18 keeps genuinely off-topic
     * chunks out while letting vendor-manual paraphrases through.
     */
    private double minRelevance = 0.18;
}

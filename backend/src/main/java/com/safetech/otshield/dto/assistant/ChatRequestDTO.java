package com.safetech.otshield.dto.assistant;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

/**
 * Incoming payload for {@code POST /api/assistant/chat}.
 *
 * <p>{@code history} is optional - when present it's the ongoing
 * conversation so the model has context. We keep it on the request rather
 * than server-side state because the assistant is stateless; each SSE call
 * is self-contained, which makes horizontal scaling trivial and avoids a
 * conversations table until we actually need persistence.
 */
@Data
public class ChatRequestDTO {

    @NotBlank
    @Size(max = 4000, message = "Question must be under 4000 characters")
    private String question;

    /** Previous turns in the same conversation, oldest first. Optional. */
    private List<HistoryTurn> history;

    /**
     * Optional - when set, the backend will persist both the user's
     * question and the assistant's final answer (plus citations) into
     * {@code research_messages} under this thread. When null the
     * conversation stays ephemeral (widget usage from dashboards).
     */
    private String threadId;

    @Data
    public static class HistoryTurn {
        /** "user" or "assistant". */
        private String role;
        private String content;
    }
}

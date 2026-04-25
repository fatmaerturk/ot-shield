package com.safetech.otshield.service.research;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.ResearchMessage;
import com.safetech.otshield.model.research.ResearchThread;
import com.safetech.otshield.repository.research.ResearchMessageRepository;
import com.safetech.otshield.repository.research.ResearchThreadRepository;
import com.safetech.otshield.service.assistant.AssistantService.AnswerMetadata;
import com.safetech.otshield.service.assistant.AssistantService.Citation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Persistence layer behind the "Threads" tab of the Research Studio.
 *
 * <p>A thread is nothing more than an ordered sequence of
 * {@link ResearchMessage} rows grouped under a title. We keep a running
 * {@code messageCount} and {@code lastQuestion} directly on the parent
 * row so the threads list can render a rich preview with a single
 * query.
 *
 * <p>Citations are serialized as JSON into the message row's
 * {@code citationsJson} TEXT column - they always travel as a whole
 * with the message and never need to be queried individually.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ThreadService {

    private final ResearchThreadRepository threadRepository;
    private final ResearchMessageRepository messageRepository;
    private final ObjectMapper objectMapper;

    /** Threads list, most recently active first. */
    public List<ResearchThread> listThreads() {
        return listThreads(null);
    }

    /** Bundle-scoped listing; null {@code bundleId} means all bundles. */
    public List<ResearchThread> listThreads(String bundleId) {
        return bundleId == null
                ? threadRepository.findAllByOrderByUpdatedAtDesc()
                : threadRepository.findByBundleIdOrderByUpdatedAtDesc(bundleId);
    }

    public Optional<ResearchThread> getThread(String threadId) {
        return threadRepository.findById(threadId);
    }

    /** Full transcript for a thread, oldest message first. */
    public List<ResearchMessage> listMessages(String threadId) {
        return messageRepository.findByThreadIdOrderByCreatedAtAsc(threadId);
    }

    /**
     * Convenience fetch for the Promote-to-Finding workflow.
     * Returns empty if the message does not exist.
     */
    public Optional<ResearchMessage> getMessage(String messageId) {
        return messageRepository.findById(messageId);
    }

    /**
     * Creates a fresh thread seeded with its first user question.
     * Title defaults to the first 80 chars of the question.
     */
    @Transactional
    public ResearchThread createThread(String firstQuestion) {
        return createThread(firstQuestion, null);
    }

    /** Create a thread inside the given bundle (nullable for legacy callers). */
    @Transactional
    public ResearchThread createThread(String firstQuestion, String bundleId) {
        LocalDateTime now = LocalDateTime.now();
        String safeQuestion = firstQuestion == null ? "" : firstQuestion.trim();
        String title = titleFromQuestion(safeQuestion);
        ResearchThread thread = ResearchThread.builder()
                .title(title)
                .lastQuestion(trim(safeQuestion, 512))
                .messageCount(0)
                .bundleId(bundleId)
                .createdAt(now)
                .updatedAt(now)
                .build();
        return threadRepository.save(thread);
    }

    /**
     * Appends a user question to the thread and bumps the metadata
     * fields. Returns the persisted message row.
     */
    @Transactional
    public ResearchMessage appendUserMessage(String threadId, String content) {
        ResearchThread thread = threadRepository.findById(threadId)
                .orElseThrow(() -> new IllegalArgumentException("Thread not found: " + threadId));

        LocalDateTime now = LocalDateTime.now();
        ResearchMessage message = messageRepository.save(ResearchMessage.builder()
                .threadId(threadId)
                .role("user")
                .content(content == null ? "" : content)
                .createdAt(now)
                .build());

        thread.setLastQuestion(trim(content, 512));
        thread.setMessageCount(thread.getMessageCount() + 1);
        thread.setUpdatedAt(now);
        threadRepository.save(thread);
        return message;
    }

    /**
     * Appends an assistant answer and its citations to the thread.
     * Citations are serialised to a compact JSON array; a null or empty
     * list becomes a null column so we don't store the literal string
     * {@code "[]"}.
     *
     * <p>Backwards-compatible overload - older call sites that don't
     * have the parsed self-assessment handy forward {@code null}, and we
     * persist without the confidence columns.
     */
    @Transactional
    public ResearchMessage appendAssistantMessage(String threadId, String content, List<Citation> citations) {
        return appendAssistantMessage(threadId, content, citations, null);
    }

    /**
     * Full-fat variant: persists the visible answer alongside the
     * model's self-reported confidence + "needs more sources" flag. Pass
     * {@code metadata = null} when the footer wasn't parsed successfully
     * (e.g. the model ignored the instruction entirely) - the message
     * is then stored without confidence columns and the UI renders it
     * as a plain bubble without the pill.
     */
    @Transactional
    public ResearchMessage appendAssistantMessage(String threadId,
                                                  String content,
                                                  List<Citation> citations,
                                                  AnswerMetadata metadata) {
        ResearchThread thread = threadRepository.findById(threadId)
                .orElseThrow(() -> new IllegalArgumentException("Thread not found: " + threadId));

        LocalDateTime now = LocalDateTime.now();
        String citationsJson = null;
        if (citations != null && !citations.isEmpty()) {
            try {
                citationsJson = objectMapper.writeValueAsString(citations);
            } catch (JsonProcessingException e) {
                log.warn("Failed to serialise citations for thread {}: {}", threadId, e.getMessage());
            }
        }

        ResearchMessage.ResearchMessageBuilder builder = ResearchMessage.builder()
                .threadId(threadId)
                .role("assistant")
                .content(content == null ? "" : content)
                .citationsJson(citationsJson)
                .createdAt(now);

        if (metadata != null) {
            builder.confidence(metadata.confidence() == null ? null : metadata.confidence().name());
            builder.needsMoreSources(metadata.needsMoreSources());
        }

        ResearchMessage message = messageRepository.save(builder.build());

        thread.setMessageCount(thread.getMessageCount() + 1);
        thread.setUpdatedAt(now);
        threadRepository.save(thread);
        return message;
    }

    /**
     * Overwrites the {@code alternatives_json} column of an existing
     * assistant message. Returns the updated message, or empty if the
     * id does not exist / is not an assistant turn.
     *
     * <p>We don't bump the parent thread's {@code updatedAt} here -
     * pulling alternatives is a read-side lens on an existing answer,
     * not a new message, and we don't want it to push the thread up
     * the "recently active" list.
     */
    @Transactional
    public Optional<ResearchMessage> writeAlternatives(String messageId, String alternativesJson) {
        return messageRepository.findById(messageId).map(msg -> {
            msg.setAlternativesJson(alternativesJson);
            return messageRepository.save(msg);
        });
    }

    /**
     * Persist the consistency-warnings JSON next to an assistant
     * message. Called at the end of a chat turn so the DTO can surface
     * the same warnings on a refresh; pulling alternatives / promoting
     * the message must not touch this field.
     */
    @Transactional
    public Optional<ResearchMessage> writeConsistency(String messageId, String consistencyJson) {
        return messageRepository.findById(messageId).map(msg -> {
            msg.setConsistencyJson(consistencyJson);
            return messageRepository.save(msg);
        });
    }

    /** Rename a thread. Returns the updated entity or empty if not found. */
    @Transactional
    public Optional<ResearchThread> renameThread(String threadId, String newTitle) {
        return threadRepository.findById(threadId).map(thread -> {
            String title = newTitle == null || newTitle.isBlank()
                    ? thread.getTitle()
                    : trim(newTitle, 256);
            thread.setTitle(title);
            thread.setUpdatedAt(LocalDateTime.now());
            return threadRepository.save(thread);
        });
    }

    /**
     * Hard deletes a thread and its messages. The FK has
     * ON DELETE CASCADE so the explicit {@code deleteByThreadId} is
     * belt-and-braces for tests running against H2 without cascades.
     */
    @Transactional
    public void deleteThread(String threadId) {
        messageRepository.deleteByThreadId(threadId);
        threadRepository.deleteById(threadId);
    }

    /**
     * Deserialises a stored message's citations back into the record
     * used by AssistantService. Returns an empty list on any failure so
     * callers never have to handle exceptions during rendering.
     */
    public List<Citation> parseCitations(String citationsJson) {
        if (citationsJson == null || citationsJson.isBlank()) {
            return Collections.emptyList();
        }
        try {
            return objectMapper.readerForListOf(Citation.class).readValue(citationsJson);
        } catch (Exception e) {
            log.debug("Could not parse citations JSON: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    private static String titleFromQuestion(String question) {
        if (question == null || question.isBlank()) {
            return "New thread";
        }
        String compact = question.replaceAll("\\s+", " ").trim();
        if (compact.length() <= 80) {
            return compact;
        }
        return compact.substring(0, 77) + "...";
    }

    private static String trim(String value, int max) {
        if (value == null) {
            return null;
        }
        String compact = value.replaceAll("\\s+", " ").trim();
        if (compact.length() <= max) {
            return compact;
        }
        return compact.substring(0, max);
    }
}

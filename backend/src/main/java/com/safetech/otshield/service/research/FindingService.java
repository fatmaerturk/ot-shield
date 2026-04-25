package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.ResearchFinding;
import com.safetech.otshield.model.research.ResearchMessage;
import com.safetech.otshield.repository.research.ResearchFindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * CRUD for the curated Findings ledger ("Findings" tab).
 *
 * <p>A finding is a copy, not a reference: when we promote a message
 * we snapshot both the text and the citations JSON so the finding
 * survives deletion of the source thread. Tags are free-form
 * comma-separated text for now; we'll normalise to a join table when
 * the UI needs server-side filtering.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FindingService {

    private final ResearchFindingRepository findingRepository;
    private final ThreadService threadService;

    /** All findings, newest first. */
    public List<ResearchFinding> listFindings() {
        return listFindings(null);
    }

    /** Bundle-scoped listing; null {@code bundleId} means all bundles. */
    public List<ResearchFinding> listFindings(String bundleId) {
        return bundleId == null
                ? findingRepository.findAllByOrderByCreatedAtDesc()
                : findingRepository.findByBundleIdOrderByCreatedAtDesc(bundleId);
    }

    public Optional<ResearchFinding> getFinding(String id) {
        return findingRepository.findById(id);
    }

    /**
     * Promotes an assistant message into a permanent finding. Copies
     * the content and citation JSON verbatim; the analyst can then
     * edit the title/text/tags via {@link #updateFinding}.
     *
     * @param messageId  source assistant message to snapshot
     * @param titleOverride  optional custom title; null/blank falls back
     *                       to a slice of the message content
     */
    @Transactional
    public ResearchFinding promoteMessage(String messageId, String titleOverride, String tags) {
        return promoteMessage(messageId, titleOverride, tags, null);
    }

    @Transactional
    public ResearchFinding promoteMessage(String messageId, String titleOverride, String tags, String bundleId) {
        ResearchMessage message = threadService.getMessage(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Message not found: " + messageId));

        if (!"assistant".equalsIgnoreCase(message.getRole())) {
            throw new IllegalArgumentException("Only assistant messages can be promoted to findings");
        }

        LocalDateTime now = LocalDateTime.now();
        String title = (titleOverride == null || titleOverride.isBlank())
                ? titleFromText(message.getContent())
                : trim(titleOverride, 256);

        ResearchFinding finding = ResearchFinding.builder()
                .title(title)
                .text(message.getContent() == null ? "" : message.getContent())
                .citationsJson(message.getCitationsJson())
                .sourceThreadId(message.getThreadId())
                .sourceMessageId(message.getId())
                .tags(tags == null ? null : trim(tags, 512))
                .bundleId(bundleId)
                .createdAt(now)
                .updatedAt(now)
                .build();
        return findingRepository.save(finding);
    }

    /**
     * Analyst-authored finding that did not originate from a chat turn.
     * Useful for quick knowledge capture without running the copilot.
     */
    @Transactional
    public ResearchFinding createFinding(String title, String text, String tags) {
        return createFinding(title, text, tags, null);
    }

    @Transactional
    public ResearchFinding createFinding(String title, String text, String tags, String bundleId) {
        LocalDateTime now = LocalDateTime.now();
        ResearchFinding finding = ResearchFinding.builder()
                .title((title == null || title.isBlank()) ? titleFromText(text) : trim(title, 256))
                .text(text == null ? "" : text)
                .citationsJson(null)
                .tags(tags == null ? null : trim(tags, 512))
                .bundleId(bundleId)
                .createdAt(now)
                .updatedAt(now)
                .build();
        return findingRepository.save(finding);
    }

    /**
     * Updates editable fields (title / text / tags). Citations and
     * provenance are immutable - promote a fresh message if the
     * sources change.
     */
    @Transactional
    public Optional<ResearchFinding> updateFinding(String id, String title, String text, String tags) {
        return findingRepository.findById(id).map(finding -> {
            if (title != null && !title.isBlank()) {
                finding.setTitle(trim(title, 256));
            }
            if (text != null) {
                finding.setText(text);
            }
            if (tags != null) {
                finding.setTags(tags.isBlank() ? null : trim(tags, 512));
            }
            finding.setUpdatedAt(LocalDateTime.now());
            return findingRepository.save(finding);
        });
    }

    @Transactional
    public void deleteFinding(String id) {
        findingRepository.deleteById(id);
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    private static String titleFromText(String text) {
        if (text == null || text.isBlank()) {
            return "Untitled finding";
        }
        String firstSentence = text.split("(?<=[.!?])\\s+", 2)[0];
        String compact = firstSentence.replaceAll("\\s+", " ").trim();
        if (compact.length() <= 120) {
            return compact;
        }
        return compact.substring(0, 117) + "...";
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

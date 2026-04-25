package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.ResearchAnnotation;
import com.safetech.otshield.model.research.ResearchAnnotation.Kind;
import com.safetech.otshield.model.research.ResearchAnnotation.TargetKind;
import com.safetech.otshield.repository.research.ResearchAnnotationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Thin service wrapper around {@link ResearchAnnotationRepository}.
 * Handles timestamp bookkeeping + a couple of convenience lookups
 * the controller layer would otherwise duplicate.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AnnotationService {

    private final ResearchAnnotationRepository repository;

    public List<ResearchAnnotation> listForTarget(TargetKind kind, String targetId) {
        return repository.findByTargetKindAndTargetIdOrderByCreatedAtAsc(kind, targetId);
    }

    /** Convenience batch fetch used by ThreadsTab to mount notes in one shot. */
    public List<ResearchAnnotation> listForTargets(TargetKind kind, List<String> targetIds) {
        if (targetIds == null || targetIds.isEmpty()) return List.of();
        return repository.findByTargetKindAndTargetIdInOrderByCreatedAtAsc(kind, targetIds);
    }

    public List<ResearchAnnotation> listForBundle(String bundleId) {
        if (bundleId == null || bundleId.isBlank()) return List.of();
        return repository.findByBundleIdOrderByCreatedAtDesc(bundleId);
    }

    @Transactional
    public ResearchAnnotation create(String bundleId, TargetKind targetKind, String targetId,
                                     Kind kind, String body, String tags, String author) {
        LocalDateTime now = LocalDateTime.now();
        ResearchAnnotation row = ResearchAnnotation.builder()
                .bundleId(bundleId)
                .targetKind(targetKind)
                .targetId(targetId)
                .kind(kind == null ? Kind.NOTE : kind)
                .body(body == null ? "" : body)
                .tags(tags)
                .author(author)
                .createdAt(now)
                .updatedAt(now)
                .build();
        return repository.save(row);
    }

    @Transactional
    public Optional<ResearchAnnotation> update(String id, Kind kind, String body, String tags) {
        return repository.findById(id).map(a -> {
            if (kind != null) a.setKind(kind);
            if (body != null) a.setBody(body);
            if (tags != null) a.setTags(tags.isBlank() ? null : tags);
            a.setUpdatedAt(LocalDateTime.now());
            return repository.save(a);
        });
    }

    @Transactional
    public boolean delete(String id) {
        if (!repository.existsById(id)) return false;
        repository.deleteById(id);
        return true;
    }
}

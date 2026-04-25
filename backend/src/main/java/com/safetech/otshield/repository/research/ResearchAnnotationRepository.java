package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchAnnotation;
import com.safetech.otshield.model.research.ResearchAnnotation.TargetKind;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * CRUD + a handful of scoped lookups for researcher annotations.
 * Kept tiny on purpose - no custom JPQL, just method-name derived
 * queries. The service layer does any heavier joining.
 */
@Repository
public interface ResearchAnnotationRepository extends JpaRepository<ResearchAnnotation, String> {

    /** All annotations in a bundle, newest first. Used by the bundle-report builder. */
    List<ResearchAnnotation> findByBundleIdOrderByCreatedAtDesc(String bundleId);

    /** Annotations targeting one object, oldest first (natural reading order). */
    List<ResearchAnnotation> findByTargetKindAndTargetIdOrderByCreatedAtAsc(
            TargetKind targetKind, String targetId);

    /** Batch fetch for a transcript: "all notes on this thread's messages". */
    List<ResearchAnnotation> findByTargetKindAndTargetIdInOrderByCreatedAtAsc(
            TargetKind targetKind, List<String> targetIds);

    /** Housekeeping - drop every annotation for a vanished target id. */
    @Modifying
    void deleteByTargetKindAndTargetId(TargetKind targetKind, String targetId);
}

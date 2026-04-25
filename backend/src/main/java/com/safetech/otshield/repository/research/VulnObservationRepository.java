package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.VulnObservation;
import com.safetech.otshield.model.research.VulnObservation.VulnSeverity;
import com.safetech.otshield.model.research.VulnObservation.VulnStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

/**
 * Repository for {@link VulnObservation}.
 *
 * <p>The VulnsTab filter bar composes multiple optional predicates; rather
 * than a dozen derived-query variants we keep a single JPQL with nullable
 * parameters ({@link #search}) plus narrow helpers used by the KPI
 * aggregator.
 *
 * <p>Count queries take their enum values as parameters rather than
 * referencing them by literal - Hibernate 6 is inconsistent about
 * {@code Enclosing$Inner} syntax in JPQL literals, and passing parameters
 * bypasses the problem entirely.
 */
public interface VulnObservationRepository extends JpaRepository<VulnObservation, String> {

    List<VulnObservation> findAllByOrderByUpdatedAtDesc();

    /** Faz 4.1: bundle-scoped listing. */
    List<VulnObservation> findByBundleIdOrderByUpdatedAtDesc(String bundleId);

    long countByStatus(VulnStatus status);

    long countBySeverity(VulnSeverity severity);

    long countByNeedsMoreSourcesTrue();

    /** Bundle-scoped KPI variants. Passing null for bundleId hits all rows. */
    long countByBundleIdAndStatus(String bundleId, VulnStatus status);

    long countByBundleIdAndNeedsMoreSourcesTrue(String bundleId);

    /**
     * How many are non-terminal. {@code bundleId} is nullable - null
     * means "across all bundles". Caller passes the set of terminal
     * statuses so we don't have to spell out the enum in JPQL.
     */
    @Query("""
            SELECT COUNT(v) FROM VulnObservation v
             WHERE v.status NOT IN :terminal
               AND (:bundleId IS NULL OR v.bundleId = :bundleId)
            """)
    long countNonTerminal(@Param("terminal") Collection<VulnStatus> terminal,
                          @Param("bundleId") String bundleId);

    /** Verified + severity in the provided set (HIGH/CRITICAL in practice). */
    @Query("""
            SELECT COUNT(v) FROM VulnObservation v
             WHERE v.status = :status
               AND v.severity IN :severities
               AND (:bundleId IS NULL OR v.bundleId = :bundleId)
            """)
    long countByStatusAndSeverityIn(@Param("status") VulnStatus status,
                                    @Param("severities") Collection<VulnSeverity> severities,
                                    @Param("bundleId") String bundleId);

    /**
     * Filter-aware listing for the Vulns table. Any null parameter is
     * treated as "no filter on this field".
     */
    @Query("""
            SELECT v FROM VulnObservation v
             WHERE (:status         IS NULL OR v.status = :status)
               AND (:severity       IS NULL OR v.severity = :severity)
               AND (:componentType  IS NULL OR v.componentType = :componentType)
               AND (:needsMoreSources IS NULL OR v.needsMoreSources = :needsMoreSources)
               AND (:bundleId        IS NULL OR v.bundleId = :bundleId)
             ORDER BY v.updatedAt DESC
            """)
    List<VulnObservation> search(@Param("status") VulnStatus status,
                                 @Param("severity") VulnSeverity severity,
                                 @Param("componentType") VulnObservation.ComponentType componentType,
                                 @Param("needsMoreSources") Boolean needsMoreSources,
                                 @Param("bundleId") String bundleId);
}

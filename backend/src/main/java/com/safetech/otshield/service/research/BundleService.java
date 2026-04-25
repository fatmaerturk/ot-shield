package com.safetech.otshield.service.research;

import com.safetech.otshield.dto.research.BundleRequestDTOs.CreateRequest;
import com.safetech.otshield.dto.research.BundleRequestDTOs.UpdateRequest;
import com.safetech.otshield.model.research.ResearchBundle;
import com.safetech.otshield.repository.research.ResearchBundleRepository;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages {@link ResearchBundle} lifecycle and, crucially, the one-time
 * migration that re-homes every pre-Faz-4.1 Research row (documents,
 * threads, findings, vuln observations) into a freshly-seeded "Default
 * Workspace" bundle.
 *
 * <p>The seeder runs on {@link PostConstruct} so it fires exactly once
 * per JVM boot, is idempotent (safe to run repeatedly), and uses native
 * UPDATE statements keyed on {@code bundle_id IS NULL} so subsequent
 * boots are no-ops. Failure to seed is logged loudly but does not crash
 * the app; bundle-aware queries gracefully treat NULL as "unassigned"
 * and the UI surfaces those rows in a dedicated "orphan" section.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BundleService {

    public static final String DEFAULT_BUNDLE_SLUG = "default";
    public static final String DEFAULT_BUNDLE_NAME = "Default Workspace";

    private final ResearchBundleRepository repo;

    @PersistenceContext
    private EntityManager em;

    // ---- Startup seeder + orphan migration ----------------------------

    @PostConstruct
    @Transactional
    public void ensureDefaultAndMigrate() {
        try {
            ResearchBundle def = repo.findBySlug(DEFAULT_BUNDLE_SLUG)
                    .orElseGet(this::createDefaultBundle);

            // Re-home every orphan row (bundle_id IS NULL) into the default
            // bundle. Done via native SQL because a bulk UPDATE is orders
            // of magnitude cheaper than loading and rewriting every entity,
            // and because these rows were created before the column even
            // existed - there's no JPA reason to hydrate them.
            int docs = exec("UPDATE research_documents SET bundle_id = ?1 WHERE bundle_id IS NULL", def.getId());
            int threads = exec("UPDATE research_threads SET bundle_id = ?1 WHERE bundle_id IS NULL", def.getId());
            int findings = exec("UPDATE research_findings SET bundle_id = ?1 WHERE bundle_id IS NULL", def.getId());
            int vulns = exec("UPDATE vulnerability_observations SET bundle_id = ?1 WHERE bundle_id IS NULL", def.getId());

            if (docs + threads + findings + vulns > 0) {
                log.info("Bundle migration: re-homed {} docs, {} threads, {} findings, {} vulns into '{}'",
                        docs, threads, findings, vulns, DEFAULT_BUNDLE_NAME);
            } else {
                log.debug("Bundle migration: nothing to re-home - all rows already bundled.");
            }
        } catch (Exception e) {
            // Never crash the boot because of this - if the tables don't
            // exist yet on a fresh install, the schema.sql step hasn't
            // run. Next boot will succeed.
            log.warn("Bundle seeder/migration skipped: {}", e.getMessage());
        }
    }

    private ResearchBundle createDefaultBundle() {
        LocalDateTime now = LocalDateTime.now();
        ResearchBundle b = ResearchBundle.builder()
                .id(UUID.randomUUID().toString())
                .name(DEFAULT_BUNDLE_NAME)
                .slug(DEFAULT_BUNDLE_SLUG)
                .tags("default")
                .description("Auto-seeded catch-all for research created before bundles existed.")
                .watchEnabled(false)
                .createdAt(now)
                .updatedAt(now)
                .build();
        ResearchBundle saved = repo.save(b);
        log.info("Seeded default research bundle '{}' (id={})", saved.getName(), saved.getId());
        return saved;
    }

    private int exec(String sql, Object... params) {
        var q = em.createNativeQuery(sql);
        for (int i = 0; i < params.length; i++) q.setParameter(i + 1, params[i]);
        return q.executeUpdate();
    }

    // ---- CRUD ---------------------------------------------------------

    public List<ResearchBundle> list() {
        return repo.findAllByOrderByUpdatedAtDesc();
    }

    public Optional<ResearchBundle> get(String id) {
        return repo.findById(id);
    }

    public Optional<ResearchBundle> getBySlug(String slug) {
        return repo.findBySlug(slug);
    }

    @Transactional
    public ResearchBundle create(CreateRequest req) {
        if (req.name() == null || req.name().isBlank()) {
            throw new IllegalArgumentException("name is required");
        }
        String slug = (req.slug() == null || req.slug().isBlank())
                ? slugify(req.name())
                : slugify(req.slug());
        slug = uniquify(slug);

        LocalDateTime now = LocalDateTime.now();
        ResearchBundle b = ResearchBundle.builder()
                .id(UUID.randomUUID().toString())
                .name(req.name().trim())
                .slug(slug)
                .tags(req.tags())
                .description(req.description())
                .watchFolderPath(req.watchFolderPath())
                .watchEnabled(Boolean.TRUE.equals(req.watchEnabled()))
                .createdAt(now)
                .updatedAt(now)
                .build();
        return repo.save(b);
    }

    @Transactional
    public Optional<ResearchBundle> update(String id, UpdateRequest req) {
        return repo.findById(id).map(b -> {
            if (req.name() != null) b.setName(req.name().trim());
            if (req.slug() != null) b.setSlug(uniquifyForUpdate(slugify(req.slug()), b.getId()));
            if (req.tags() != null) b.setTags(req.tags());
            if (req.description() != null) b.setDescription(req.description());
            if (req.watchFolderPath() != null) b.setWatchFolderPath(req.watchFolderPath());
            if (req.watchEnabled() != null) b.setWatchEnabled(req.watchEnabled());
            b.setUpdatedAt(LocalDateTime.now());
            return repo.save(b);
        });
    }

    /**
     * Hard delete. Child rows have their {@code bundle_id} set to NULL
     * via the FK {@code ON DELETE SET NULL}; those become visible under
     * the "unassigned" section until they are re-homed manually.
     */
    @Transactional
    public void delete(String id) {
        repo.findById(id).ifPresent(repo::delete);
    }

    // ---- Roll-up counters (used by the sidebar DTO builder) ----------

    public long countDocuments(String bundleId) {
        return scalar("SELECT COUNT(*) FROM research_documents WHERE bundle_id = ?1", bundleId);
    }

    public long countThreads(String bundleId) {
        return scalar("SELECT COUNT(*) FROM research_threads WHERE bundle_id = ?1", bundleId);
    }

    public long countFindings(String bundleId) {
        return scalar("SELECT COUNT(*) FROM research_findings WHERE bundle_id = ?1", bundleId);
    }

    public long countVulns(String bundleId) {
        return scalar("SELECT COUNT(*) FROM vulnerability_observations WHERE bundle_id = ?1", bundleId);
    }

    private long scalar(String sql, Object param) {
        try {
            Object result = em.createNativeQuery(sql).setParameter(1, param).getSingleResult();
            return result == null ? 0L : ((Number) result).longValue();
        } catch (Exception e) {
            log.debug("Scalar count failed for sql='{}': {}", sql, e.getMessage());
            return 0L;
        }
    }

    // ---- Helpers ------------------------------------------------------

    private static String slugify(String raw) {
        if (raw == null) return "bundle";
        String s = raw.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("^-+|-+$", "");
        if (s.isBlank()) s = "bundle";
        return s.length() <= 120 ? s : s.substring(0, 120);
    }

    /** Appends {@code -N} until the slug is unique. */
    private String uniquify(String base) {
        String candidate = base;
        int n = 2;
        while (repo.findBySlug(candidate).isPresent()) {
            candidate = base + "-" + n++;
            if (n > 500) { // runaway guard
                candidate = base + "-" + UUID.randomUUID().toString().substring(0, 8);
                break;
            }
        }
        return candidate;
    }

    /** Like {@link #uniquify} but allows the current bundle to keep its own slug. */
    private String uniquifyForUpdate(String base, String keepId) {
        Optional<ResearchBundle> held = repo.findBySlug(base);
        if (held.isEmpty() || held.get().getId().equals(keepId)) return base;
        return uniquify(base);
    }
}

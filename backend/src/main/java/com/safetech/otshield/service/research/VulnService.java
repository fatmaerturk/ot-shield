package com.safetech.otshield.service.research;

import com.safetech.otshield.dto.research.VulnKpiDTO;
import com.safetech.otshield.dto.research.VulnRequestDTOs.CreateRequest;
import com.safetech.otshield.dto.research.VulnRequestDTOs.PromoteRequest;
import com.safetech.otshield.dto.research.VulnRequestDTOs.TransitionRequest;
import com.safetech.otshield.dto.research.VulnRequestDTOs.UpdateRequest;
import com.safetech.otshield.model.research.ResearchMessage;
import com.safetech.otshield.model.research.VulnEvent;
import com.safetech.otshield.model.research.VulnObservation;
import com.safetech.otshield.model.research.VulnObservation.ComponentType;
import com.safetech.otshield.model.research.VulnObservation.VulnConfidence;
import com.safetech.otshield.model.research.VulnObservation.VulnSeverity;
import com.safetech.otshield.model.research.VulnObservation.VulnStatus;
import com.safetech.otshield.repository.research.VulnEventRepository;
import com.safetech.otshield.repository.research.VulnObservationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Business logic behind the Vulns tab.
 *
 * <p>Responsible for:
 * <ul>
 *   <li>CRUD over {@link VulnObservation}</li>
 *   <li>Promoting an existing {@link ResearchMessage} into a new
 *       observation (citations copied verbatim)</li>
 *   <li>Validating state-machine transitions and appending the matching
 *       {@link VulnEvent} so the audit trail is consistent</li>
 *   <li>Aggregating KPI counts for the tab header</li>
 * </ul>
 *
 * <p>All mutating methods are {@code @Transactional} so the observation
 * row and its event row land (or fail) together.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VulnService {

    private final VulnObservationRepository vulnRepository;
    private final VulnEventRepository eventRepository;
    private final ThreadService threadService;

    /**
     * Legal state transitions. Kept as an adjacency map so we can show
     * the frontend which buttons to enable without duplicating the rules.
     *
     * <ul>
     *   <li>DRAFT           &rarr; UNDER_REVIEW, DISMISSED, FALSE_POSITIVE</li>
     *   <li>UNDER_REVIEW    &rarr; VERIFIED, DRAFT, DISMISSED, FALSE_POSITIVE</li>
     *   <li>VERIFIED        &rarr; MITIGATED, UNDER_REVIEW</li>
     *   <li>MITIGATED       &rarr; (none - terminal)</li>
     *   <li>DISMISSED       &rarr; (none - terminal, but re-openable via EDIT)</li>
     *   <li>FALSE_POSITIVE  &rarr; (none - terminal)</li>
     * </ul>
     */
    private static final Map<VulnStatus, EnumSet<VulnStatus>> LEGAL_TRANSITIONS;
    static {
        LEGAL_TRANSITIONS = new EnumMap<>(VulnStatus.class);
        LEGAL_TRANSITIONS.put(VulnStatus.DRAFT,
                EnumSet.of(VulnStatus.UNDER_REVIEW, VulnStatus.DISMISSED, VulnStatus.FALSE_POSITIVE));
        LEGAL_TRANSITIONS.put(VulnStatus.UNDER_REVIEW,
                EnumSet.of(VulnStatus.VERIFIED, VulnStatus.DRAFT, VulnStatus.DISMISSED, VulnStatus.FALSE_POSITIVE));
        LEGAL_TRANSITIONS.put(VulnStatus.VERIFIED,
                EnumSet.of(VulnStatus.MITIGATED, VulnStatus.UNDER_REVIEW));
        LEGAL_TRANSITIONS.put(VulnStatus.MITIGATED,     EnumSet.noneOf(VulnStatus.class));
        LEGAL_TRANSITIONS.put(VulnStatus.DISMISSED,     EnumSet.noneOf(VulnStatus.class));
        LEGAL_TRANSITIONS.put(VulnStatus.FALSE_POSITIVE, EnumSet.noneOf(VulnStatus.class));
    }

    /** Statuses that take an observation out of the active queue. */
    private static final EnumSet<VulnStatus> TERMINAL_STATUSES = EnumSet.of(
            VulnStatus.MITIGATED, VulnStatus.DISMISSED, VulnStatus.FALSE_POSITIVE);

    /** Severities that count as high-risk for the "Verified · high" KPI. */
    private static final EnumSet<VulnSeverity> HIGH_RISK_SEVERITIES = EnumSet.of(
            VulnSeverity.HIGH, VulnSeverity.CRITICAL);

    // ---- Reads ---------------------------------------------------------

    public List<VulnObservation> list() {
        return list(null);
    }

    /** Bundle-scoped listing; null {@code bundleId} means all bundles. */
    public List<VulnObservation> list(String bundleId) {
        return bundleId == null
                ? vulnRepository.findAllByOrderByUpdatedAtDesc()
                : vulnRepository.findByBundleIdOrderByUpdatedAtDesc(bundleId);
    }

    public List<VulnObservation> search(VulnStatus status,
                                        VulnSeverity severity,
                                        ComponentType componentType,
                                        Boolean needsMoreSources,
                                        String bundleId) {
        return vulnRepository.search(status, severity, componentType, needsMoreSources, bundleId);
    }

    public Optional<VulnObservation> get(String id) {
        return vulnRepository.findById(id);
    }

    public List<VulnEvent> events(String vulnId) {
        return eventRepository.findByVulnIdOrderByCreatedAtAsc(vulnId);
    }

    public VulnKpiDTO kpi() {
        return kpi(null);
    }

    /** Bundle-scoped KPI; null {@code bundleId} means cross-bundle totals. */
    public VulnKpiDTO kpi(String bundleId) {
        return new VulnKpiDTO(
                vulnRepository.countNonTerminal(TERMINAL_STATUSES, bundleId),
                bundleId == null
                        ? vulnRepository.countByNeedsMoreSourcesTrue()
                        : vulnRepository.countByBundleIdAndNeedsMoreSourcesTrue(bundleId),
                bundleId == null
                        ? vulnRepository.countByStatus(VulnStatus.UNDER_REVIEW)
                        : vulnRepository.countByBundleIdAndStatus(bundleId, VulnStatus.UNDER_REVIEW),
                vulnRepository.countByStatusAndSeverityIn(VulnStatus.VERIFIED, HIGH_RISK_SEVERITIES, bundleId),
                bundleId == null
                        ? vulnRepository.countByStatus(VulnStatus.MITIGATED)
                        : vulnRepository.countByBundleIdAndStatus(bundleId, VulnStatus.MITIGATED)
        );
    }

    // ---- Writes --------------------------------------------------------

    /** Manual create. Starts life in {@code DRAFT}. */
    @Transactional
    public VulnObservation create(CreateRequest req) {
        LocalDateTime now = LocalDateTime.now();
        VulnObservation v = VulnObservation.builder()
                .title(required(req.title(), "title"))
                .summary(req.summary())
                .componentType(parseComponent(req.componentType()))
                .componentRef(req.componentRef())
                .affectedProduct(req.affectedProduct())
                .severity(parseSeverity(req.severity()))
                .cveId(req.cveId())
                .cvssV31(req.cvssV31())
                .confidence(parseConfidence(req.confidence()))
                .needsMoreSources(Boolean.TRUE.equals(req.needsMoreSources()))
                .status(VulnStatus.DRAFT)
                .alternativeHypotheses(req.alternativeHypotheses())
                .tags(req.tags())
                .bundleId(req.bundleId())
                .createdAt(now)
                .updatedAt(now)
                .createdBy(req.createdBy())
                .build();
        VulnObservation saved = vulnRepository.save(v);
        appendEvent(saved.getId(), VulnEvent.EventKind.CREATED, null, null,
                "Manually created as " + saved.getStatus(), req.createdBy());
        return saved;
    }

    /**
     * Promote an assistant message into a new observation. The message
     * content becomes the {@code summary}, and the citations it was
     * rendered with are copied into {@code citationsJson} so the
     * observation is self-contained if the thread is later deleted.
     */
    @Transactional
    public VulnObservation promote(PromoteRequest req) {
        if (req.messageId() == null || req.messageId().isBlank()) {
            throw new IllegalArgumentException("messageId is required for promote");
        }
        ResearchMessage message = threadService.getMessage(req.messageId())
                .orElseThrow(() -> new IllegalArgumentException("Source message not found: " + req.messageId()));
        if (!"assistant".equals(message.getRole())) {
            throw new IllegalArgumentException("Only assistant messages can be promoted to a vulnerability");
        }

        LocalDateTime now = LocalDateTime.now();
        String title = (req.title() == null || req.title().isBlank())
                ? deriveTitle(message.getContent())
                : req.title().trim();

        VulnObservation v = VulnObservation.builder()
                .title(title)
                .summary(message.getContent())
                .componentType(parseComponent(req.componentType()))
                .componentRef(req.componentRef())
                .affectedProduct(req.affectedProduct())
                .severity(parseSeverity(req.severity()))
                .confidence(parseConfidence(req.confidence()))
                .needsMoreSources(Boolean.TRUE.equals(req.needsMoreSources()))
                .status(VulnStatus.DRAFT)
                .sourceThreadId(req.threadId() != null ? req.threadId() : message.getThreadId())
                .sourceMessageId(message.getId())
                .citationsJson(message.getCitationsJson())
                .alternativeHypotheses(req.alternativeHypotheses())
                .tags(req.tags())
                .bundleId(req.bundleId())
                .createdAt(now)
                .updatedAt(now)
                .createdBy(req.createdBy())
                .build();
        VulnObservation saved = vulnRepository.save(v);
        appendEvent(saved.getId(), VulnEvent.EventKind.PROMOTED, null, null,
                "Promoted from thread message " + message.getId(), req.createdBy());
        return saved;
    }

    /** Patch semantics: null field means "leave as-is". */
    @Transactional
    public Optional<VulnObservation> update(String id, UpdateRequest req, String actor) {
        return vulnRepository.findById(id).map(v -> {
            if (req.title() != null) v.setTitle(req.title());
            if (req.summary() != null) v.setSummary(req.summary());
            if (req.componentType() != null) v.setComponentType(parseComponent(req.componentType()));
            if (req.componentRef() != null) v.setComponentRef(req.componentRef());
            if (req.affectedProduct() != null) v.setAffectedProduct(req.affectedProduct());
            if (req.severity() != null) v.setSeverity(parseSeverity(req.severity()));
            if (req.cveId() != null) v.setCveId(req.cveId());
            if (req.cvssV31() != null) v.setCvssV31(req.cvssV31());
            if (req.confidence() != null) v.setConfidence(parseConfidence(req.confidence()));
            if (req.needsMoreSources() != null) v.setNeedsMoreSources(req.needsMoreSources());
            if (req.mitigationSummary() != null) v.setMitigationSummary(req.mitigationSummary());
            if (req.alternativeHypotheses() != null) v.setAlternativeHypotheses(req.alternativeHypotheses());
            if (req.tags() != null) v.setTags(req.tags());
            v.setUpdatedAt(LocalDateTime.now());
            VulnObservation saved = vulnRepository.save(v);
            appendEvent(saved.getId(), VulnEvent.EventKind.EDITED, null, null,
                    "Fields updated", actor);
            return saved;
        });
    }

    /** Run a status transition and log it. */
    @Transactional
    public Optional<VulnObservation> transition(String id, TransitionRequest req) {
        VulnStatus to;
        try {
            to = VulnStatus.valueOf(req.toStatus());
        } catch (Exception e) {
            throw new IllegalArgumentException("Unknown target status: " + req.toStatus());
        }
        return vulnRepository.findById(id).map(v -> {
            VulnStatus from = v.getStatus();
            EnumSet<VulnStatus> allowed = LEGAL_TRANSITIONS.getOrDefault(from, EnumSet.noneOf(VulnStatus.class));
            if (!allowed.contains(to)) {
                throw new IllegalStateException(
                        "Illegal transition " + from + " -> " + to +
                        ". Allowed from " + from + ": " + allowed);
            }
            v.setStatus(to);
            v.setUpdatedAt(LocalDateTime.now());
            if (to == VulnStatus.VERIFIED) {
                v.setVerifiedBy(req.actor());
            }
            VulnObservation saved = vulnRepository.save(v);
            appendEvent(saved.getId(), VulnEvent.EventKind.TRANSITION, from, to,
                    req.comment(), req.actor());
            return saved;
        });
    }

    @Transactional
    public void delete(String id) {
        // FK is ON DELETE CASCADE at the DB level; explicit call keeps
        // JPA session state consistent and lets tests running against
        // H2 (where the cascade isn't honoured) still pass.
        eventRepository.deleteByVulnId(id);
        vulnRepository.deleteById(id);
    }

    // ---- Helpers -------------------------------------------------------

    private void appendEvent(String vulnId,
                             VulnEvent.EventKind kind,
                             VulnStatus from,
                             VulnStatus to,
                             String comment,
                             String actor) {
        eventRepository.save(VulnEvent.builder()
                .vulnId(vulnId)
                .kind(kind)
                .fromStatus(from)
                .toStatus(to)
                .comment(comment)
                .actor(actor)
                .createdAt(LocalDateTime.now())
                .build());
    }

    private static ComponentType parseComponent(String raw) {
        if (raw == null || raw.isBlank()) return ComponentType.OTHER;
        try { return ComponentType.valueOf(raw); }
        catch (Exception e) { return ComponentType.OTHER; }
    }

    private static VulnSeverity parseSeverity(String raw) {
        if (raw == null || raw.isBlank()) return VulnSeverity.INFO;
        try { return VulnSeverity.valueOf(raw); }
        catch (Exception e) { return VulnSeverity.INFO; }
    }

    private static VulnConfidence parseConfidence(String raw) {
        if (raw == null || raw.isBlank()) return VulnConfidence.LOW;
        try { return VulnConfidence.valueOf(raw); }
        catch (Exception e) { return VulnConfidence.LOW; }
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    /** First 120 chars of the message, whitespace-collapsed. */
    private static String deriveTitle(String content) {
        if (content == null || content.isBlank()) return "Untitled observation";
        String compact = content.replaceAll("\\s+", " ").trim();
        return compact.length() <= 120 ? compact : compact.substring(0, 117) + "...";
    }

    /**
     * Expose the transition rules to the controller so the frontend can
     * render only the buttons that are actually legal.
     */
    public EnumSet<VulnStatus> allowedTransitions(VulnStatus from) {
        return LEGAL_TRANSITIONS.getOrDefault(from, EnumSet.noneOf(VulnStatus.class));
    }
}

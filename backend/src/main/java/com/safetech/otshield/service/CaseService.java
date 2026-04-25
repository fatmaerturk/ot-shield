package com.safetech.otshield.service;

import com.safetech.otshield.dto.cases.*;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.*;
import com.safetech.otshield.repository.AlertRepository;
import com.safetech.otshield.repository.CaseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.Year;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CaseService {

    private final CaseRepository caseRepository;
    private final AlertRepository alertRepository;

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public Page<CaseDTO> list(CaseStatus status, CasePriority priority, String assigneeId,
                              String search, int page, int size, String sortBy, String sortDir) {
        Sort sort = "desc".equalsIgnoreCase(sortDir) ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);
        return caseRepository
                .findWithFilters(status, priority, assigneeId, search, pageable)
                .map(this::toListDTO);
    }

    @Transactional(readOnly = true)
    public Optional<CaseDTO> get(String id) {
        return caseRepository.findById(id).map(this::toDetailDTO);
    }

    @Transactional(readOnly = true)
    public CaseStatsDTO stats() {
        LocalDateTime sevenDaysAgo = LocalDateTime.now().minusDays(7);

        long total = caseRepository.count();
        long newCount = caseRepository.countByStatus(CaseStatus.NEW);
        long triaging = caseRepository.countByStatus(CaseStatus.TRIAGING);
        long investigating = caseRepository.countByStatus(CaseStatus.INVESTIGATING);
        long contained = caseRepository.countByStatus(CaseStatus.CONTAINED);

        long resolved7d = caseRepository.countResolvedSince(sevenDaysAgo);
        long fp7d = caseRepository.countByStatusIn(List.of(CaseStatus.FALSE_POSITIVE));

        Map<String, Long> statusDist = new LinkedHashMap<>();
        for (CaseStatus s : CaseStatus.values()) {
            statusDist.put(s.name(), caseRepository.countByStatus(s));
        }

        Map<String, Long> priorityDist = new LinkedHashMap<>();
        for (CasePriority p : CasePriority.values()) {
            priorityDist.put(p.name(), caseRepository.countByPriority(p));
        }

        return CaseStatsDTO.builder()
                .total(total)
                .open(newCount + triaging + investigating)
                .inProgress(triaging + investigating)
                .contained(contained)
                .resolved7d(resolved7d)
                .falsePositive7d(fp7d)
                .critical(caseRepository.countByPriority(CasePriority.CRITICAL))
                .high(caseRepository.countByPriority(CasePriority.HIGH))
                .medium(caseRepository.countByPriority(CasePriority.MEDIUM))
                .low(caseRepository.countByPriority(CasePriority.LOW))
                .avgMttResolveSeconds7d(caseRepository.avgMttResolveSince(sevenDaysAgo))
                .avgMttAcknowledgeSeconds7d(caseRepository.avgMttAcknowledgeSince(sevenDaysAgo))
                .statusDistribution(statusDist)
                .priorityDistribution(priorityDist)
                .build();
    }

    // ------------------------------------------------------------------
    // Create / update / transition
    // ------------------------------------------------------------------

    @Transactional
    public CaseDTO create(CreateCaseRequest req) {
        String caseNumber = nextCaseNumber();

        Case c = Case.builder()
                .caseNumber(caseNumber)
                .title(req.getTitle() != null ? req.getTitle() : "Untitled case")
                .description(req.getDescription())
                .status(CaseStatus.NEW)
                .priority(req.getPriority() != null ? req.getPriority() : CasePriority.MEDIUM)
                .severity(req.getSeverity())
                .category(req.getCategory() != null ? req.getCategory() : CaseCategory.OTHER)
                .assigneeId(req.getAssigneeId())
                .assigneeName(req.getAssigneeName())
                .reporterId(req.getReporterId())
                .reporterName(req.getReporterName() != null ? req.getReporterName() : "system")
                .tags(req.getTags() != null ? new HashSet<>(req.getTags()) : new HashSet<>())
                .build();

        Case saved = caseRepository.save(c);
        logTimeline(saved, CaseTimelineEntryType.CREATED, saved.getReporterName(),
                "Case created", null);

        // Link alerts if provided
        if (req.getAlertIds() != null && !req.getAlertIds().isEmpty()) {
            for (String alertId : req.getAlertIds()) {
                linkAlertInternal(saved, alertId, saved.getReporterName());
            }
            // Seed title/severity from first alert if not provided
            Alert first = saved.getLinkedAlerts().stream().findFirst().orElse(null);
            if (first != null) {
                if (req.getTitle() == null || req.getTitle().isBlank() || "Untitled case".equals(saved.getTitle())) {
                    saved.setTitle(first.getTitle());
                }
                if (saved.getSeverity() == null) {
                    saved.setSeverity(first.getSeverity());
                }
            }
        }

        if (saved.getAssigneeName() != null) {
            logTimeline(saved, CaseTimelineEntryType.ASSIGNED, saved.getReporterName(),
                    "Assigned to " + saved.getAssigneeName(),
                    Map.of("assigneeId", saved.getAssigneeId(), "assigneeName", saved.getAssigneeName()));
        }

        return toDetailDTO(caseRepository.save(saved));
    }

    @Transactional
    public Optional<CaseDTO> update(String id, UpdateCaseRequest req, String actor) {
        return caseRepository.findById(id).map(c -> {
            if (req.getTitle() != null) c.setTitle(req.getTitle());
            if (req.getDescription() != null) c.setDescription(req.getDescription());
            if (req.getCategory() != null) c.setCategory(req.getCategory());
            if (req.getSeverity() != null) c.setSeverity(req.getSeverity());
            if (req.getResolutionSummary() != null) c.setResolutionSummary(req.getResolutionSummary());

            if (req.getTags() != null) {
                Set<String> added = new HashSet<>(req.getTags());
                added.removeAll(c.getTags());
                Set<String> removed = new HashSet<>(c.getTags());
                removed.removeAll(req.getTags());
                c.setTags(new HashSet<>(req.getTags()));
                added.forEach(t -> logTimeline(c, CaseTimelineEntryType.TAG_ADDED, actor, "Tag added: " + t, null));
                removed.forEach(t -> logTimeline(c, CaseTimelineEntryType.TAG_REMOVED, actor, "Tag removed: " + t, null));
            }

            if (req.getPriority() != null && req.getPriority() != c.getPriority()) {
                CasePriority old = c.getPriority();
                c.setPriority(req.getPriority());
                logTimeline(c, CaseTimelineEntryType.PRIORITY_CHANGE, actor,
                        "Priority " + old + " → " + req.getPriority(),
                        Map.of("from", old.name(), "to", req.getPriority().name()));
            }

            return toDetailDTO(caseRepository.save(c));
        });
    }

    @Transactional
    public Optional<CaseDTO> transition(String id, CaseTransitionRequest req) {
        return caseRepository.findById(id).map(c -> {
            CaseStatus from = c.getStatus();
            CaseStatus to = req.getToStatus();
            if (to == null || from == to) return toDetailDTO(c);

            LocalDateTime now = LocalDateTime.now();
            c.setStatus(to);

            // Transition side-effects
            if (c.getAcknowledgedAt() == null
                    && (to == CaseStatus.TRIAGING || to == CaseStatus.INVESTIGATING
                    || to == CaseStatus.CONTAINED || to == CaseStatus.RESOLVED)) {
                c.setAcknowledgedAt(now);
                c.setMttAcknowledgeSeconds(ChronoUnit.SECONDS.between(c.getCreatedAt(), now));
            }
            if (to == CaseStatus.CONTAINED && c.getContainedAt() == null) {
                c.setContainedAt(now);
                c.setMttContainSeconds(ChronoUnit.SECONDS.between(c.getCreatedAt(), now));
            }
            if ((to == CaseStatus.RESOLVED || to == CaseStatus.FALSE_POSITIVE) && c.getResolvedAt() == null) {
                c.setResolvedAt(now);
                c.setMttResolveSeconds(ChronoUnit.SECONDS.between(c.getCreatedAt(), now));
                if (req.getResolutionSummary() != null) {
                    c.setResolutionSummary(req.getResolutionSummary());
                }
            }
            if (to == CaseStatus.CLOSED && c.getClosedAt() == null) {
                c.setClosedAt(now);
            }

            logTimeline(c, CaseTimelineEntryType.STATUS_CHANGE, req.getActorName(),
                    (req.getNote() != null && !req.getNote().isBlank())
                            ? req.getNote()
                            : "Status " + from + " → " + to,
                    Map.of("from", from.name(), "to", to.name()));

            if ((to == CaseStatus.RESOLVED || to == CaseStatus.FALSE_POSITIVE)
                    && req.getResolutionSummary() != null && !req.getResolutionSummary().isBlank()) {
                logTimeline(c, CaseTimelineEntryType.RESOLUTION, req.getActorName(),
                        req.getResolutionSummary(), null);
            }

            return toDetailDTO(caseRepository.save(c));
        });
    }

    @Transactional
    public Optional<CaseDTO> assign(String id, CaseAssignRequest req) {
        return caseRepository.findById(id).map(c -> {
            String actor = req.getActorName();
            if (req.getAssigneeId() == null || req.getAssigneeId().isBlank()) {
                String prev = c.getAssigneeName();
                c.setAssigneeId(null);
                c.setAssigneeName(null);
                logTimeline(c, CaseTimelineEntryType.UNASSIGNED, actor,
                        "Unassigned" + (prev != null ? " (from " + prev + ")" : ""), null);
            } else {
                c.setAssigneeId(req.getAssigneeId());
                c.setAssigneeName(req.getAssigneeName());
                logTimeline(c, CaseTimelineEntryType.ASSIGNED, actor,
                        "Assigned to " + req.getAssigneeName(),
                        Map.of("assigneeId", req.getAssigneeId(), "assigneeName", req.getAssigneeName()));
            }
            return toDetailDTO(caseRepository.save(c));
        });
    }

    @Transactional
    public boolean delete(String id) {
        if (!caseRepository.existsById(id)) return false;
        caseRepository.deleteById(id);
        return true;
    }

    // ------------------------------------------------------------------
    // Comments / artifacts / alert links
    // ------------------------------------------------------------------

    @Transactional
    public Optional<CaseDTO> addComment(String id, CaseCommentRequest req) {
        return caseRepository.findById(id).map(c -> {
            logTimeline(c, CaseTimelineEntryType.COMMENT, req.getActorName(), req.getContent(), null);
            return toDetailDTO(caseRepository.save(c));
        });
    }

    @Transactional
    public Optional<CaseArtifactDTO> addArtifact(String id, CaseArtifactRequest req) {
        return caseRepository.findById(id).map(c -> {
            CaseArtifact a = CaseArtifact.builder()
                    .caseEntity(c)
                    .artifactType(req.getArtifactType() != null ? req.getArtifactType() : CaseArtifactType.OTHER)
                    .value(req.getValue())
                    .label(req.getLabel())
                    .description(req.getDescription())
                    .malicious(req.getMalicious())
                    .addedBy(req.getActorName())
                    .build();
            c.getArtifacts().add(a);
            logTimeline(c, CaseTimelineEntryType.ARTIFACT_ADDED, req.getActorName(),
                    a.getArtifactType() + ": " + a.getValue(),
                    Map.of("type", String.valueOf(a.getArtifactType()), "value", String.valueOf(a.getValue())));
            Case saved = caseRepository.save(c);
            CaseArtifact persisted = saved.getArtifacts().stream()
                    .filter(x -> Objects.equals(x.getValue(), a.getValue())
                            && Objects.equals(x.getArtifactType(), a.getArtifactType()))
                    .reduce((first, second) -> second) // newest
                    .orElse(a);
            return toArtifactDTO(persisted);
        });
    }

    @Transactional
    public boolean removeArtifact(String caseId, String artifactId, String actor) {
        return caseRepository.findById(caseId).map(c -> {
            Optional<CaseArtifact> target = c.getArtifacts().stream()
                    .filter(a -> a.getId().equals(artifactId)).findFirst();
            if (target.isEmpty()) return false;
            CaseArtifact removed = target.get();
            c.getArtifacts().remove(removed);
            logTimeline(c, CaseTimelineEntryType.ARTIFACT_REMOVED, actor,
                    removed.getArtifactType() + ": " + removed.getValue(), null);
            caseRepository.save(c);
            return true;
        }).orElse(false);
    }

    @Transactional
    public Optional<CaseDTO> linkAlert(String caseId, String alertId, String actor) {
        return caseRepository.findById(caseId).map(c -> {
            linkAlertInternal(c, alertId, actor);
            return toDetailDTO(caseRepository.save(c));
        });
    }

    @Transactional
    public Optional<CaseDTO> unlinkAlert(String caseId, String alertId, String actor) {
        return caseRepository.findById(caseId).map(c -> {
            Optional<Alert> match = c.getLinkedAlerts().stream()
                    .filter(a -> a.getId().equals(alertId)).findFirst();
            if (match.isPresent()) {
                c.getLinkedAlerts().remove(match.get());
                logTimeline(c, CaseTimelineEntryType.ALERT_UNLINKED, actor,
                        "Unlinked alert " + alertId, Map.of("alertId", alertId));
            }
            return toDetailDTO(caseRepository.save(c));
        });
    }

    private void linkAlertInternal(Case c, String alertId, String actor) {
        Optional<Alert> alertOpt = alertRepository.findById(alertId);
        if (alertOpt.isEmpty()) {
            log.warn("linkAlertInternal: alert {} not found", alertId);
            return;
        }
        Alert alert = alertOpt.get();
        if (c.getLinkedAlerts().add(alert)) {
            logTimeline(c, CaseTimelineEntryType.ALERT_LINKED, actor,
                    "Linked alert: " + alert.getTitle(),
                    Map.of("alertId", alert.getId(), "alertTitle", alert.getTitle()));
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private void logTimeline(Case c, CaseTimelineEntryType type, String actor, String content, Map<String, String> meta) {
        CaseTimelineEntry e = CaseTimelineEntry.builder()
                .caseEntity(c)
                .entryType(type)
                .actorName(actor != null ? actor : "system")
                .content(content)
                .metadataJson(meta != null ? simpleJson(meta) : null)
                .ts(LocalDateTime.now())
                .build();
        c.getTimeline().add(e);
    }

    private static String simpleJson(Map<String, String> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (!first) sb.append(',');
            sb.append('"').append(escape(e.getKey())).append("\":\"")
                    .append(escape(String.valueOf(e.getValue()))).append('"');
            first = false;
        }
        return sb.append('}').toString();
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String nextCaseNumber() {
        int year = Year.now().getValue();
        String prefix = "CASE-" + year + "-";
        Optional<String> maxOpt = caseRepository.findMaxCaseNumberForPrefix(prefix);
        int next = 1;
        if (maxOpt.isPresent()) {
            try {
                String tail = maxOpt.get().substring(prefix.length());
                next = Integer.parseInt(tail) + 1;
            } catch (Exception ignore) { /* fall through */ }
        }
        return prefix + String.format("%04d", next);
    }

    // ------------------------------------------------------------------
    // Mappers
    // ------------------------------------------------------------------

    private CaseDTO toListDTO(Case c) {
        return CaseDTO.builder()
                .id(c.getId())
                .caseNumber(c.getCaseNumber())
                .title(c.getTitle())
                .description(c.getDescription())
                .status(c.getStatus())
                .priority(c.getPriority())
                .severity(c.getSeverity())
                .category(c.getCategory())
                .assigneeId(c.getAssigneeId())
                .assigneeName(c.getAssigneeName())
                .reporterId(c.getReporterId())
                .reporterName(c.getReporterName())
                .createdAt(c.getCreatedAt())
                .updatedAt(c.getUpdatedAt())
                .acknowledgedAt(c.getAcknowledgedAt())
                .containedAt(c.getContainedAt())
                .resolvedAt(c.getResolvedAt())
                .closedAt(c.getClosedAt())
                .resolutionSummary(c.getResolutionSummary())
                .mttAcknowledgeSeconds(c.getMttAcknowledgeSeconds())
                .mttContainSeconds(c.getMttContainSeconds())
                .mttResolveSeconds(c.getMttResolveSeconds())
                .tags(c.getTags() != null ? new HashSet<>(c.getTags()) : new HashSet<>())
                .linkedAlertCount(c.getLinkedAlerts() != null ? c.getLinkedAlerts().size() : 0)
                .artifactCount(c.getArtifacts() != null ? c.getArtifacts().size() : 0)
                .timelineCount(c.getTimeline() != null ? c.getTimeline().size() : 0)
                .build();
    }

    private CaseDTO toDetailDTO(Case c) {
        CaseDTO dto = toListDTO(c);
        dto.setLinkedAlertIds(c.getLinkedAlerts().stream()
                .map(Alert::getId).collect(Collectors.toList()));
        dto.setTimeline(c.getTimeline().stream()
                .map(this::toTimelineDTO).collect(Collectors.toList()));
        dto.setArtifacts(c.getArtifacts().stream()
                .map(this::toArtifactDTO).collect(Collectors.toList()));
        return dto;
    }

    private CaseTimelineEntryDTO toTimelineDTO(CaseTimelineEntry e) {
        return CaseTimelineEntryDTO.builder()
                .id(e.getId())
                .caseId(e.getCaseEntity() != null ? e.getCaseEntity().getId() : null)
                .ts(e.getTs())
                .entryType(e.getEntryType())
                .actorId(e.getActorId())
                .actorName(e.getActorName())
                .content(e.getContent())
                .metadataJson(e.getMetadataJson())
                .build();
    }

    private CaseArtifactDTO toArtifactDTO(CaseArtifact a) {
        return CaseArtifactDTO.builder()
                .id(a.getId())
                .caseId(a.getCaseEntity() != null ? a.getCaseEntity().getId() : null)
                .artifactType(a.getArtifactType())
                .value(a.getValue())
                .label(a.getLabel())
                .description(a.getDescription())
                .addedBy(a.getAddedBy())
                .addedAt(a.getAddedAt())
                .malicious(a.getMalicious())
                .build();
    }

    /** Suppress unused warning for AlertSeverity import when Lombok trims mapping. */
    @SuppressWarnings("unused")
    private static final Class<?> __unusedSeverity = AlertSeverity.class;
}

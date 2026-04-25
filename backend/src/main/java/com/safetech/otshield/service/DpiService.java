package com.safetech.otshield.service;

import com.safetech.otshield.dto.DpiEventDTO;
import com.safetech.otshield.dto.FunctionCodeStatDTO;
import com.safetech.otshield.dto.ObservedConnectionDTO;
import com.safetech.otshield.model.DpiEvent;
import com.safetech.otshield.repository.DpiEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Read-oriented façade over {@link DpiEventRepository}. This is the backend of
 * the Network Topology edge/node detail panels and of the Dashboard DPI modal.
 *
 * <p>Everything here is strictly query; event creation happens via
 * {@link PcapAnalysisService#analyzePcapFile(String)} after the dissectors run.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DpiService {

    private final DpiEventRepository repository;

    // ------------------------------------------------------------------
    // List / search
    // ------------------------------------------------------------------

    /**
     * Flexible search - any filter may be null to mean "don't constrain".
     * {@code ip} matches either src OR dst (node-centric view).
     */
    public Page<DpiEventDTO> search(String sourceIp, String destinationIp, String ip,
                                     String protocol, String pduKind,
                                     LocalDateTime from, LocalDateTime to,
                                     int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<DpiEvent> events = repository.search(
                emptyToNull(sourceIp),
                emptyToNull(destinationIp),
                emptyToNull(ip),
                emptyToNull(protocol),
                emptyToNull(pduKind),
                from, to, pageable);
        return events.map(e -> DpiEventDTO.fromEntity(e, false));
    }

    public Optional<DpiEventDTO> findById(String id) {
        return repository.findById(id).map(e -> DpiEventDTO.fromEntity(e, true));
    }

    // ------------------------------------------------------------------
    // Aggregations - "function-code histograms" that drive the rare-command
    // badge on the topology edge tooltip and the DPI modal.
    // ------------------------------------------------------------------

    public List<FunctionCodeStatDTO> functionCodeStats(String sourceIp, String destinationIp,
                                                       LocalDateTime from, LocalDateTime to) {
        List<Object[]> rows = repository.functionCodeStats(
                emptyToNull(sourceIp), emptyToNull(destinationIp), from, to);
        return rows.stream().map(DpiService::toStatDTO).toList();
    }

    public List<FunctionCodeStatDTO> functionCodeStatsForNode(String ip,
                                                              LocalDateTime from, LocalDateTime to) {
        if (ip == null || ip.isBlank()) return List.of();
        List<Object[]> rows = repository.functionCodeStatsForNode(ip, from, to);
        return rows.stream().map(DpiService::toStatDTO).toList();
    }

    public List<Object[]> writeCommsSummary(LocalDateTime from, LocalDateTime to) {
        return repository.writeCommsSummary(from, to);
    }

    /**
     * Every distinct src↔dst pair observed in the DPI stream, projected onto
     * the topology-friendly DTO. Feeds the real baseline edges on the Network
     * Topology page.
     */
    public List<ObservedConnectionDTO> observedConnections(LocalDateTime from, LocalDateTime to) {
        List<Object[]> rows = repository.observedConnections(from, to);
        return rows.stream().map(DpiService::toConnectionDTO).toList();
    }

    private static ObservedConnectionDTO toConnectionDTO(Object[] row) {
        return ObservedConnectionDTO.builder()
                .sourceIp(asString(row, 0))
                .destinationIp(asString(row, 1))
                .protocol(asString(row, 2))
                .count(asLong(row, 3))
                .build();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static FunctionCodeStatDTO toStatDTO(Object[] row) {
        return FunctionCodeStatDTO.builder()
                .protocol(asString(row, 0))
                .functionCode(asString(row, 1))
                .functionName(asString(row, 2))
                .count(asLong(row, 3))
                .build();
    }

    private static String asString(Object[] row, int i) {
        return row != null && row.length > i && row[i] != null ? row[i].toString() : null;
    }

    private static long asLong(Object[] row, int i) {
        if (row == null || row.length <= i || row[i] == null) return 0L;
        if (row[i] instanceof Number n) return n.longValue();
        try { return Long.parseLong(row[i].toString()); } catch (NumberFormatException e) { return 0L; }
    }

    private static String emptyToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}

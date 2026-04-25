package com.safetech.otshield.controller;

import com.safetech.otshield.dto.DpiEventDTO;
import com.safetech.otshield.dto.FunctionCodeStatDTO;
import com.safetech.otshield.dto.ObservedConnectionDTO;
import com.safetech.otshield.service.DpiService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST surface for Deep-Packet-Inspection events captured by the dissectors
 * during PCAP analysis. Feeds:
 * <ul>
 *   <li>Network Topology edge detail panel - {@code /api/dpi/events?sourceIp=…&destinationIp=…}</li>
 *   <li>Network Topology node detail panel - {@code /api/dpi/events?ip=…}</li>
 *   <li>Rare-command badge on edge tooltip - {@code /api/dpi/function-stats}</li>
 *   <li>Dashboard DPI modal - {@code /api/dpi/events/{id}} (full field JSON)</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/dpi")
@RequiredArgsConstructor
@Slf4j
public class DpiController {

    private final DpiService dpiService;

    /**
     * Search DPI events with flexible, optional filters. All query params are
     * optional; timestamps are ISO-8601 local date-times ("2024-04-20T12:00:00").
     *
     * <p>{@code ip} matches events where the given IP is either source OR
     * destination and is intended for the node-detail panel. {@code sourceIp}
     * and {@code destinationIp} pin the edge direction exactly.
     */
    @GetMapping("/events")
    public ResponseEntity<Page<DpiEventDTO>> searchEvents(
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String destinationIp,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String protocol,
            @RequestParam(required = false) String pduKind,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        LocalDateTime fromLdt = parseTs(from);
        LocalDateTime toLdt = parseTs(to);
        Page<DpiEventDTO> result = dpiService.search(
                sourceIp, destinationIp, ip, protocol, pduKind, fromLdt, toLdt, page, size);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/events/{id}")
    public ResponseEntity<DpiEventDTO> getEvent(@PathVariable String id) {
        Optional<DpiEventDTO> event = dpiService.findById(id);
        return event.map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    /**
     * Function-code histogram for a specific src↔dst pair (edge histogram) or,
     * when both are null, the global histogram.
     */
    @GetMapping("/function-stats")
    public ResponseEntity<List<FunctionCodeStatDTO>> functionStats(
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String destinationIp,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to
    ) {
        LocalDateTime fromLdt = parseTs(from);
        LocalDateTime toLdt = parseTs(to);
        return ResponseEntity.ok(
                dpiService.functionCodeStats(sourceIp, destinationIp, fromLdt, toLdt));
    }

    /** Function-code histogram for any traffic touching a given IP. */
    @GetMapping("/stats/node")
    public ResponseEntity<List<FunctionCodeStatDTO>> nodeStats(
            @RequestParam String ip,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to
    ) {
        LocalDateTime fromLdt = parseTs(from);
        LocalDateTime toLdt = parseTs(to);
        return ResponseEntity.ok(
                dpiService.functionCodeStatsForNode(ip, fromLdt, toLdt));
    }

    /**
     * Every distinct src↔dst pair ever observed in the dissector stream.
     * Feeds the Network Topology page so real pcap-derived Modbus/S7 edges
     * replace the demo scenario whenever we have any real traffic.
     */
    @GetMapping("/observed-connections")
    public ResponseEntity<List<ObservedConnectionDTO>> observedConnections(
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to
    ) {
        LocalDateTime fromLdt = parseTs(from);
        LocalDateTime toLdt = parseTs(to);
        return ResponseEntity.ok(dpiService.observedConnections(fromLdt, toLdt));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "DpiService",
                "timestamp", LocalDateTime.now().toString()
        ));
    }

    private static LocalDateTime parseTs(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            return LocalDateTime.parse(raw);
        } catch (DateTimeParseException e) {
            log.debug("Could not parse timestamp '{}' - treating as null", raw);
            return null;
        }
    }
}

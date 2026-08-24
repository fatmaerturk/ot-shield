package com.safetech.otshield.controller;

import com.safetech.otshield.dto.attacker.AttackerSummaryDTO;
import com.safetech.otshield.dto.attacker.AttackerTimelineDTO;
import com.safetech.otshield.service.AttackerTimelineService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Attacker-centric views: a ranked "campaigns" list and, per attacker IP, the
 * full stitched kill-chain timeline across every real telemetry store.
 */
@RestController
@RequestMapping("/api/attackers")
@RequiredArgsConstructor
@Slf4j
public class AttackerController {

    private final AttackerTimelineService attackerTimelineService;

    /** Ranked list of attacker IPs with their kill-chain reach. */
    @GetMapping
    public ResponseEntity<List<AttackerSummaryDTO>> list(
            @RequestParam(defaultValue = "25") int limit) {
        return ResponseEntity.ok(attackerTimelineService.listAttackers(limit));
    }

    /** Full chronological kill-chain timeline for one attacker IP. */
    @GetMapping("/{ip}/timeline")
    public ResponseEntity<AttackerTimelineDTO> timeline(@PathVariable String ip) {
        log.debug("Building attacker timeline for {}", ip);
        return ResponseEntity.ok(attackerTimelineService.getTimeline(ip));
    }
}

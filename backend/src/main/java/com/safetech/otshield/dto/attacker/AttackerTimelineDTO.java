package com.safetech.otshield.dto.attacker;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/** The full stitched campaign timeline for a single attacker IP. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackerTimelineDTO {
    private String ip;
    private String country;
    private LocalDateTime firstSeen;
    private LocalDateTime lastSeen;
    private int totalEvents;
    /** Distinct kill-chain phases the attacker reached, in canonical order. */
    private List<KillChainPhase> reachedPhases;
    private String highestSeverity;
    private List<TargetedAssetDTO> targetedAssets;
    /** Case numbers already opened for this IP. */
    private List<String> caseNumbers;
    /** Chronological, oldest first. */
    private List<TimelineEventDTO> events;
}

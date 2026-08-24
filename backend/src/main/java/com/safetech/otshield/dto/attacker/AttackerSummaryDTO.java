package com.safetech.otshield.dto.attacker;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/** One row in the ranked "campaigns / top attackers" list. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackerSummaryDTO {
    private String ip;
    private String country;
    private LocalDateTime firstSeen;
    private LocalDateTime lastSeen;
    private int eventCount;
    private List<KillChainPhase> reachedPhases;
    private String highestSeverity;
    private int targetedAssetCount;
    /** Reached IMPACT - a write against a real or decoy device. */
    private boolean breached;
}

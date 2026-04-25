package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.time.Instant;
import java.util.List;

/**
 * Compact attacker record for the intel list panel.
 * Detailed TTP matrix and campaign links come from the detail endpoint.
 */
@Data
public class AttackerIntelSummaryDTO {
    private String ip;
    private String asn;
    private String asnName;
    private String country;
    private String countryName;
    private Instant firstSeen;
    private Instant lastSeen;
    private Long engagementCount;
    private Long distinctDecoysHit;
    private Integer threatScore;         // 0..100
    private List<String> tags;           // behavior tags
    private List<String> protocols;      // protocols exercised
    private String dominantTactic;       // most observed ATT&CK tactic
    private Integer distinctTechniques;  // unique T-IDs observed
    private Boolean blocked;
    private Boolean quarantined;
    private List<Integer> activitySparkline; // last 12 buckets (engagement count)
}

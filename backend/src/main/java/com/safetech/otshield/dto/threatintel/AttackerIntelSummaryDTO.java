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

    // Connection-nature classification (real IP intel; NOT a guaranteed VPN yes/no).
    private String anonymityCategory;    // TOR_EXIT | VPN_PROVIDER | HOSTING_DATACENTER | RESIDENTIAL_ISP | INTERNAL | NOT_ASSESSED
    private String anonymityLabel;       // human label
    private String anonymityConfidence;  // HIGH | MEDIUM | LOW | NONE
    private Boolean anonymized;           // true = Tor / VPN / hosting (not an apparently-direct residential source)
    private String anonymityNote;        // honest caveat / basis
    private List<String> anonymitySignals; // which signals fired
}

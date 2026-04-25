package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.time.Instant;
import java.util.List;

/** Threat-intel profile for a single attacker IP. */
@Data
public class AttackerProfileDTO {
    private String ip;
    private String asn;            // e.g. "AS14061"
    private String asnName;        // e.g. "DigitalOcean"
    private String country;        // ISO-2 code
    private String countryName;    // e.g. "Romania"
    private Instant firstSeen;
    private Instant lastSeen;
    private Long engagementCount;
    private Long distinctDecoysHit;
    private Integer threatScore;   // 0..100
    private List<String> tags;     // e.g. ["RECONNAISSANCE", "BRUTEFORCE"]
    private String threatIntelSource; // e.g. "AlienVault OTX"
    private Boolean blocked;
    private Boolean quarantined;
}

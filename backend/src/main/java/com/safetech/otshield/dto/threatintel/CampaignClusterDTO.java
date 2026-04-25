package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.util.List;

/**
 * A cluster of attacker IPs that share the same behavioral fingerprint +
 * overlapping infrastructure (ASN / country / targeted decoys).
 */
@Data
public class CampaignClusterDTO {
    private String id;                           // stable cluster id
    private String name;                         // e.g. "Eastern Europe OPC-UA scan, Q2"
    private String fingerprintHash;              // links to BehavioralFingerprintDTO.hash
    private List<String> memberIps;              // IPs in the cluster
    private List<String> sharedAsns;
    private List<String> targetedDecoyIds;
    private List<String> topTechniques;          // e.g. ["T0846","T0855"]
    private Integer severityScore;               // 0..100 aggregate
    private Integer memberCount;
    private String summary;                      // one-line narrative
}

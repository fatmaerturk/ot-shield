package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.util.List;
import java.util.Map;

/**
 * Behavioral fingerprint for an attacker. Computed from engagement/event stream.
 * Used to cluster similar attackers and to show a quick "profile card".
 */
@Data
public class BehavioralFingerprintDTO {
    private String hash;                          // short hash of dominant TTP set + protocol mix
    private String pattern;                       // human label e.g. "Recon -> Discovery -> Impair"
    private List<String> dominantTactics;         // top 3
    private Map<String, Integer> protocolMix;     // protocol -> event count
    private Map<String, Integer> functionCodeMix; // functionCode -> count (top operations)
    private Integer repetitionScore;              // 0..100 how repetitive the behavior is
    private Integer nightRatio;                   // 0..100 % of activity during attacker-local night
    private Integer burstiness;                   // 0..100 bursty vs steady
    private List<String> notableAnomalies;        // e.g. "Unit ID scan", "Raw CIP identity probe"
}

package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.util.List;

/**
 * MITRE ATT&CK for ICS matrix structure: ordered tactics (kill chain) with
 * their child techniques. Used both as a static matrix reference (empty hits)
 * and as a per-attacker filled matrix (hits[] populated).
 */
@Data
public class TtpMatrixDTO {
    private List<Tactic> tactics;

    @Data
    public static class Tactic {
        private String id;             // e.g. "TA0108"
        private String name;           // e.g. "Initial Access"
        private Integer order;         // kill-chain order
        private List<Technique> techniques;
    }

    @Data
    public static class Technique {
        private String id;                 // e.g. "T0883"
        private String name;               // e.g. "Internet Accessible Device"
        private Integer observationCount;  // how many times we saw this TTP
        private Integer confidence;        // 0..100 aggregated confidence
        private List<String> evidenceEventIds; // engagement-event ids that triggered
    }
}

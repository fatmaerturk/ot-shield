package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.util.List;
import java.util.Map;

/** Hero-strip stats for the Decoy Layer page. */
@Data
public class DecoyStatsDTO {
    private Long activeEngagements;
    private Long engagementsLast24h;
    private Long uniqueAttackersLast24h;
    private Long decoysRunning;
    private Long decoysTotal;
    private Map<String, Long> engagementsByProtocol;  // "MODBUS" -> 12
    private List<TopMitreEntry> topMitreTactics;
    private List<TopProtocolOpEntry> topProtocolOps;

    @Data
    public static class TopMitreEntry {
        private String tactic;
        private Long count;
    }

    @Data
    public static class TopProtocolOpEntry {
        private String op;
        private Long count;
    }
}

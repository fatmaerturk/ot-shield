package com.safetech.otshield.dto.cases;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseStatsDTO {
    private long total;
    private long open;            // NEW + TRIAGING + INVESTIGATING
    private long inProgress;      // TRIAGING + INVESTIGATING
    private long contained;
    private long resolved7d;
    private long falsePositive7d;

    private long critical;
    private long high;
    private long medium;
    private long low;

    /** Avg MTTR in seconds over last 7 days of resolved cases. */
    private Double avgMttResolveSeconds7d;
    /** Avg MTT acknowledge in seconds over last 7 days. */
    private Double avgMttAcknowledgeSeconds7d;

    /** Status -> count (all-time). */
    private Map<String, Long> statusDistribution;
    /** Priority -> count (open cases only). */
    private Map<String, Long> priorityDistribution;
}

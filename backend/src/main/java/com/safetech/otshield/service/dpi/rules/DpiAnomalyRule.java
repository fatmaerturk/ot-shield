package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.DpiEvent;

import java.util.List;

/**
 * One DPI → anomaly detection rule. Implementations are pure, deterministic
 * functions of {@code (batch, ctx)} so they can be unit tested without a
 * database and composed freely by {@link DpiAnomalyRuleEngine}.
 *
 * <p>A rule returns one {@link AnomalyDTO} per <i>deduplicated</i> finding -
 * for example, a single "unauthorized write from 10.0.3.5 to 10.0.0.12"
 * anomaly even when the batch contains dozens of Modbus Write PDUs for that
 * same src→dst pair. The engine itself also deduplicates across rules, but
 * intra-rule deduplication lets each rule pick its own grouping key.
 *
 * <p>Rules should populate at minimum: {@code title}, {@code description},
 * {@code anomalyType}, {@code severity}, {@code sourceIp}, {@code destinationIp},
 * {@code protocol}, {@code evidence}, and {@code indicators} (which must
 * include the {@code ruleId()} + any matched function code so the frontend
 * can group anomalies by rule).
 */
public interface DpiAnomalyRule {

    /**
     * Stable machine-readable id. Used for deduplication across re-runs and
     * shown in the anomaly's indicator list so the UI can filter by rule.
     */
    String ruleId();

    /**
     * Evaluate the rule against a batch of DPI events and return zero or more
     * anomalies. Implementations <b>must not</b> persist anything - the engine
     * owns persistence.
     *
     * @param batch DPI events from a single pcap upload, not null, not empty.
     * @param ctx   shared reference data (asset purdue levels, baseline
     *              histogram, session id); never null.
     */
    List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx);
}

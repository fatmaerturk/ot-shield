package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.model.DpiEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Flags Modbus / S7 exception responses ({@code is_exception=true}). A single
 * exception is often benign (transient read of a dead register) but a burst
 * of them from the <i>same</i> source is a strong indicator of a scanner or a
 * misbehaving client.
 *
 * <p>Severity:
 * <ul>
 *   <li><b>LOW</b> - 1–4 exceptions from the same src→dst pair.</li>
 *   <li><b>MEDIUM</b> - 5 or more exceptions, suggesting a brute-force
 *       register scan or repeated failed command.</li>
 * </ul>
 *
 * <p>MITRE ATT&amp;CK for ICS: {@code T0846 - Remote System Discovery} /
 * {@code T0806 - Brute Force I/O}.
 */
@Component
@Slf4j
public class ExceptionResponseRule implements DpiAnomalyRule {

    public static final String RULE_ID = "dpi.exception_response";

    /** At or above this count, the severity is escalated from LOW to MEDIUM. */
    public static final int BURST_THRESHOLD = 5;

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx) {
        if (batch == null || batch.isEmpty()) return List.of();

        // Group by (src, dst, protocol) - keep the grouping tight so one noisy
        // client doesn't bleed into a different target's anomaly.
        Map<String, List<DpiEvent>> groups = new HashMap<>();
        for (DpiEvent ev : batch) {
            if (!Boolean.TRUE.equals(ev.getIsException())) continue;
            if (ev.getSourceIp() == null || ev.getDestinationIp() == null) continue;
            String key = ev.getSourceIp() + "->" + ev.getDestinationIp() + "|" + safe(ev.getProtocol());
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(ev);
        }

        List<AnomalyDTO> results = new ArrayList<>();
        for (Map.Entry<String, List<DpiEvent>> entry : groups.entrySet()) {
            List<DpiEvent> events = entry.getValue();
            DpiEvent first = events.get(0);
            int count = events.size();
            boolean burst = count >= BURST_THRESHOLD;
            Anomaly.AnomalySeverity sev = burst
                    ? Anomaly.AnomalySeverity.MEDIUM
                    : Anomaly.AnomalySeverity.LOW;

            StringBuilder evidence = new StringBuilder();
            evidence.append(count).append(" ").append(safe(first.getProtocol()))
                    .append(" exception response(s) from ").append(first.getSourceIp())
                    .append(" to ").append(first.getDestinationIp()).append(". ");
            int sample = Math.min(3, count);
            evidence.append("Sample function codes: ");
            for (int i = 0; i < sample; i++) {
                DpiEvent e = events.get(i);
                if (i > 0) evidence.append(", ");
                evidence.append(safe(e.getFunctionCode()))
                        .append(" (").append(safe(e.getFunctionName())).append(")");
            }
            if (count > sample) evidence.append(", …");
            if (burst) {
                evidence.append("\nBurst of ").append(count)
                        .append(" exceptions suggests a register/address scan or repeated failed command.");
            }

            List<String> indicators = new ArrayList<>();
            indicators.add("rule:" + RULE_ID);
            indicators.add("exception_count:" + count);
            indicators.add("protocol:" + safe(first.getProtocol()));
            if (ctx.getPcapSessionId() != null) indicators.add("pcap_session:" + ctx.getPcapSessionId());

            AnomalyDTO dto = AnomalyDTO.builder()
                    .title((burst ? "Burst of " : "") + safe(first.getProtocol())
                            + " exception responses (" + count + ")")
                    .description("Target " + first.getDestinationIp() + " returned " + count
                            + " protocol-level exception response(s) to " + first.getSourceIp()
                            + ". A single exception can be benign, but repeated failures typically "
                            + "indicate an attacker probing invalid registers or commands.")
                    .anomalyType(Anomaly.AnomalyType.PROTOCOL_VIOLATION)
                    .severity(sev)
                    .status(Anomaly.AnomalyStatus.DETECTED)
                    .sourceIp(first.getSourceIp())
                    .destinationIp(first.getDestinationIp())
                    .sourcePort(first.getSourcePort())
                    .destinationPort(first.getDestinationPort())
                    .protocol(first.getProtocol())
                    .evidence(evidence.toString())
                    .mitigationSteps("Review the source host for scanning tools; if the source is an engineering workstation, check whether its logic configuration still matches the target device's register map.")
                    .recommendations("Rate-limit / alert on ICS exception responses and investigate any burst above the threshold.")
                    .confidenceScore(burst ? 0.7 : 0.4)
                    .riskScore(burst ? 50.0 : 25.0)
                    .mitreTactic("Discovery")
                    .mitreTechnique("Remote System Discovery")
                    .mitreId("T0846")
                    .indicators(indicators)
                    .detectedAt(first.getEventTime() != null ? first.getEventTime() : LocalDateTime.now())
                    .isActive(true)
                    .createdBy("dpi-engine")
                    .build();
            results.add(dto);
        }

        if (!results.isEmpty()) {
            log.info("[{}] produced {} anomaly(ies)", RULE_ID, results.size());
        }
        return results;
    }

    private static String safe(String s) {
        return s == null ? "?" : s;
    }
}

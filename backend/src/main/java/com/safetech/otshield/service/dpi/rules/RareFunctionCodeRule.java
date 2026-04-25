package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.model.DpiEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Fires when a batch contains a {@code (protocol, functionCode)} combination
 * that has never (or almost never) been seen historically.
 *
 * <p>Baseline data comes from {@link RuleContext#getGlobalFunctionCodeCounts()}:
 * the count <i>excludes</i> the current batch (the engine pre-filters out the
 * current pcap session before building the histogram), so a function code
 * appearing for the first time has count {@code 0}.
 *
 * <p>Severity:
 * <ul>
 *   <li><b>MEDIUM</b> - completely first-seen function code for this protocol.</li>
 *   <li><b>LOW</b> - historically rare (count &lt; {@value #RARE_THRESHOLD}).</li>
 * </ul>
 *
 * <p>Grouping: one anomaly per unique {@code (protocol, functionCode,
 * sourceIp, destinationIp)}. This keeps Wireshark-style scan patterns from
 * producing one anomaly per packet while still letting multiple PLCs each
 * raise their own alert when hit by the same scanner.
 *
 * <p>MITRE ATT&amp;CK for ICS: {@code T0846 - Remote System Discovery}.
 */
@Component
@Slf4j
public class RareFunctionCodeRule implements DpiAnomalyRule {

    public static final String RULE_ID = "dpi.rare_function_code";

    /** Function codes with historical count below this are considered "rare". */
    public static final long RARE_THRESHOLD = 3;

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx) {
        if (batch == null || batch.isEmpty()) return List.of();

        // De-duplicate by (protocol, fc, src, dst) so one scanner hitting one
        // target with the same exotic code only produces one anomaly.
        Map<String, List<DpiEvent>> groups = new HashMap<>();
        for (DpiEvent ev : batch) {
            if (ev.getFunctionCode() == null || ev.getFunctionCode().isBlank()) continue;
            String key = safe(ev.getProtocol()) + "|" + ev.getFunctionCode()
                    + "|" + safe(ev.getSourceIp()) + "|" + safe(ev.getDestinationIp());
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(ev);
        }

        // Track which fcKeys we already emitted an anomaly for in this pass so
        // we don't emit duplicates when the same fc hits multiple targets - we
        // still emit per (src,dst) target, but not the same rule twice for the
        // same tuple.
        Set<String> emitted = new HashSet<>();
        List<AnomalyDTO> results = new ArrayList<>();

        for (Map.Entry<String, List<DpiEvent>> entry : groups.entrySet()) {
            List<DpiEvent> events = entry.getValue();
            DpiEvent first = events.get(0);
            String fcKey = RuleContext.fcKey(first.getProtocol(), first.getFunctionCode());
            long historicalCount = ctx.getGlobalFunctionCodeCounts()
                    .getOrDefault(fcKey, 0L);

            if (historicalCount >= RARE_THRESHOLD) continue; // not rare enough

            String dedupKey = fcKey + "|" + first.getSourceIp() + "|" + first.getDestinationIp();
            if (!emitted.add(dedupKey)) continue;

            boolean firstSeen = historicalCount == 0;
            Anomaly.AnomalySeverity sev = firstSeen
                    ? Anomaly.AnomalySeverity.MEDIUM
                    : Anomaly.AnomalySeverity.LOW;

            String evidence = String.format(
                    "Function code %s (%s) on protocol %s observed %d time(s) in this pcap from %s → %s. "
                            + "Historical occurrences across all prior traffic: %d. %s",
                    safe(first.getFunctionCode()),
                    safe(first.getFunctionName()),
                    safe(first.getProtocol()),
                    events.size(),
                    first.getSourceIp(),
                    first.getDestinationIp(),
                    historicalCount,
                    firstSeen ? "This function code has never been seen before on this network." : "Historically rare.");

            List<String> indicators = new ArrayList<>();
            indicators.add("rule:" + RULE_ID);
            indicators.add("protocol:" + safe(first.getProtocol()));
            indicators.add("function_code:" + first.getFunctionCode());
            if (first.getFunctionName() != null) indicators.add("function_name:" + first.getFunctionName());
            indicators.add("historical_count:" + historicalCount);
            if (ctx.getPcapSessionId() != null) indicators.add("pcap_session:" + ctx.getPcapSessionId());

            AnomalyDTO dto = AnomalyDTO.builder()
                    .title((firstSeen ? "New " : "Rare ") + safe(first.getProtocol())
                            + " function code " + safe(first.getFunctionCode())
                            + (first.getFunctionName() != null ? " (" + first.getFunctionName() + ")" : ""))
                    .description("An uncommon " + safe(first.getProtocol())
                            + " function code appeared between " + first.getSourceIp()
                            + " and " + first.getDestinationIp() + ". Unexpected function codes are a "
                            + "classic indicator of reconnaissance, firmware exploitation, or "
                            + "misconfigured tooling.")
                    .anomalyType(Anomaly.AnomalyType.PROTOCOL_ANOMALY)
                    .severity(sev)
                    .status(Anomaly.AnomalyStatus.DETECTED)
                    .sourceIp(first.getSourceIp())
                    .destinationIp(first.getDestinationIp())
                    .sourcePort(first.getSourcePort())
                    .destinationPort(first.getDestinationPort())
                    .protocol(first.getProtocol())
                    .evidence(evidence)
                    .mitigationSteps("Verify whether the function code corresponds to an expected engineering operation. If not, block the source host and capture the full session for forensic review.")
                    .recommendations("Maintain a per-zone allowlist of permitted Modbus / S7 / IEC104 function codes and drop anything outside that list at the OT firewall.")
                    .confidenceScore(firstSeen ? 0.7 : 0.5)
                    .riskScore(firstSeen ? 55.0 : 35.0)
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

package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.model.DpiEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Fires when a single source touches many distinct destinations in one capture -
 * the fan-out signature of a network scan / device enumeration sweep, a classic
 * pre-attack reconnaissance step in OT.
 *
 * <p>MITRE ATT&amp;CK for ICS: {@code T0846 - Remote System Discovery}.
 */
@Component
@Slf4j
public class ScanEnumerationRule implements DpiAnomalyRule {

    public static final String RULE_ID = "dpi.scan_enumeration";
    public static final int SCAN_THRESHOLD = 8; // distinct destinations from one source

    @Override
    public String ruleId() { return RULE_ID; }

    @Override
    public List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx) {
        if (batch == null || batch.isEmpty()) return List.of();

        Map<String, Set<String>> targets = new HashMap<>();
        Map<String, DpiEvent> sample = new HashMap<>();
        for (DpiEvent ev : batch) {
            String src = ev.getSourceIp(), dst = ev.getDestinationIp();
            if (src == null || dst == null) continue;
            targets.computeIfAbsent(src, k -> new HashSet<>()).add(dst);
            sample.putIfAbsent(src, ev);
        }

        List<AnomalyDTO> out = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : targets.entrySet()) {
            int n = e.getValue().size();
            if (n < SCAN_THRESHOLD) continue;
            String src = e.getKey();
            DpiEvent f = sample.get(src);
            boolean big = n >= SCAN_THRESHOLD * 2;

            List<String> ind = new ArrayList<>(List.of("rule:" + RULE_ID,
                "scanner:" + src, "distinct_targets:" + n, "protocol:" + safe(f.getProtocol())));
            if (ctx.getPcapSessionId() != null) ind.add("pcap_session:" + ctx.getPcapSessionId());

            out.add(AnomalyDTO.builder()
                .title("Enumeration sweep from " + src + " (" + n + " targets)")
                .description(src + " contacted " + n + " distinct devices in a single capture over " + safe(f.getProtocol())
                    + ". A single host fanning out to many endpoints is the hallmark of a network scan or asset "
                    + "enumeration - reconnaissance that typically precedes an attack.")
                .anomalyType(Anomaly.AnomalyType.COMMUNICATION_PATTERN)
                .severity(big ? Anomaly.AnomalySeverity.HIGH : Anomaly.AnomalySeverity.MEDIUM)
                .status(Anomaly.AnomalyStatus.DETECTED)
                .sourceIp(src).destinationIp(f.getDestinationIp())
                .protocol(f.getProtocol())
                .evidence(src + " reached " + n + " distinct destinations in this pcap.")
                .mitigationSteps("Identify whether the source is a sanctioned scanner/EWS. If not, isolate it and review what it discovered.")
                .recommendations("Restrict which hosts may broadcast/scan; alert on any single source exceeding a per-zone fan-out threshold.")
                .confidenceScore(big ? 0.8 : 0.6).riskScore(big ? 65.0 : 45.0)
                .mitreTactic("Discovery").mitreTechnique("Remote System Discovery").mitreId("T0846")
                .indicators(ind)
                .detectedAt(f.getEventTime() != null ? f.getEventTime() : LocalDateTime.now())
                .isActive(true).createdBy("dpi-engine")
                .build());
        }
        if (!out.isEmpty()) log.info("[{}] produced {} anomaly(ies)", RULE_ID, out.size());
        return out;
    }

    private static String safe(String s) { return s == null ? "?" : s; }
}

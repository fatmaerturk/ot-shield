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
 * Flags any Modbus / S7 PDU whose {@code is_write} flag is true and whose
 * source sits at a <i>higher</i> Purdue level than its destination
 * - i.e. an enterprise / DMZ host writing down into a control or field
 * network, or a level-skipping write across a zone boundary.
 *
 * <p>In a healthy IEC 62443 plant, writes <b>only</b> flow between L2 (area
 * SCADA) and L1 (PLC) inside a zone. A write that crosses <i>two or more</i>
 * Purdue levels is almost always either a misconfigured engineering station
 * or a lateral-movement attempt and deserves an anomaly.
 *
 * <p>If either endpoint's Purdue level is unknown (the IP is not a registered
 * asset), the rule conservatively does <b>not</b> fire - the plant map is
 * incomplete and false positives on unmapped hosts would be noisy. The
 * topology view already surfaces such traffic as a plain "observed
 * connection" edge.
 *
 * <p>Severity:
 * <ul>
 *   <li><b>CRITICAL</b> - write reaches L0/L1 from L3 or above (IT → OT).</li>
 *   <li><b>HIGH</b> - write crosses exactly one zone boundary downward.</li>
 * </ul>
 *
 * <p>MITRE ATT&amp;CK for ICS: {@code T0836 - Modify Parameter} / {@code T0855
 * - Unauthorized Command Message}.
 */
@Component
@Slf4j
public class UnauthorizedWriteRule implements DpiAnomalyRule {

    public static final String RULE_ID = "dpi.unauthorized_write";

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx) {
        if (batch == null || batch.isEmpty()) return List.of();

        // Group write events by (src, dst, protocol) so many PDUs on the same
        // conduit collapse into a single anomaly with an aggregated evidence
        // count. This matches what users expect in the topology view - one red
        // edge per attacker→victim pair, not one anomaly per packet.
        Map<String, List<DpiEvent>> groups = new HashMap<>();
        for (DpiEvent ev : batch) {
            if (!Boolean.TRUE.equals(ev.getIsWrite())) continue;
            if (ev.getSourceIp() == null || ev.getDestinationIp() == null) continue;
            Integer srcLvl = ctx.purdueLevelOf(ev.getSourceIp());
            Integer dstLvl = ctx.purdueLevelOf(ev.getDestinationIp());
            if (srcLvl == null || dstLvl == null) continue; // can't judge - skip
            // Only fires on downward writes (higher level writing into lower).
            // Same-level writes between peers inside one zone are allowed.
            if (srcLvl <= dstLvl) continue;
            int delta = srcLvl - dstLvl;
            if (delta < 1) continue;
            String key = ev.getSourceIp() + "->" + ev.getDestinationIp() + "|" + safe(ev.getProtocol());
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(ev);
        }

        List<AnomalyDTO> results = new ArrayList<>();
        for (Map.Entry<String, List<DpiEvent>> entry : groups.entrySet()) {
            List<DpiEvent> events = entry.getValue();
            DpiEvent first = events.get(0);
            Integer srcLvl = ctx.purdueLevelOf(first.getSourceIp());
            Integer dstLvl = ctx.purdueLevelOf(first.getDestinationIp());
            int delta = (srcLvl != null && dstLvl != null) ? srcLvl - dstLvl : 1;

            // IT (L3+) reaching into OT (L1/L0) is the canonical "this is very
            // bad" scenario - pop it to CRITICAL. Single-boundary crossings are
            // HIGH.
            Anomaly.AnomalySeverity sev =
                    (srcLvl != null && srcLvl >= 3 && dstLvl != null && dstLvl <= 1)
                            ? Anomaly.AnomalySeverity.CRITICAL
                            : (delta >= 2
                                ? Anomaly.AnomalySeverity.CRITICAL
                                : Anomaly.AnomalySeverity.HIGH);

            StringBuilder evidence = new StringBuilder();
            evidence.append("Cross-zone write detected. ")
                    .append(events.size()).append(" write PDU(s) from L").append(srcLvl)
                    .append(" host ").append(first.getSourceIp())
                    .append(" to L").append(dstLvl).append(" host ")
                    .append(first.getDestinationIp()).append(".\n");
            int sample = Math.min(3, events.size());
            evidence.append("Sample function codes: ");
            for (int i = 0; i < sample; i++) {
                DpiEvent e = events.get(i);
                if (i > 0) evidence.append(", ");
                evidence.append(safe(e.getFunctionCode()))
                        .append(" (").append(safe(e.getFunctionName())).append(")");
            }
            if (events.size() > sample) evidence.append(", …");

            List<String> indicators = new ArrayList<>();
            indicators.add("rule:" + RULE_ID);
            indicators.add("src_level:L" + srcLvl);
            indicators.add("dst_level:L" + dstLvl);
            indicators.add("write_count:" + events.size());
            if (ctx.getPcapSessionId() != null) {
                indicators.add("pcap_session:" + ctx.getPcapSessionId());
            }

            AnomalyDTO dto = AnomalyDTO.builder()
                    .title("Unauthorized cross-zone write (L" + srcLvl + " → L" + dstLvl + ")")
                    .description("A host at Purdue Level " + srcLvl + " issued " + events.size()
                            + " write command(s) into a Level " + dstLvl + " device. "
                            + "Writes should normally stay within a zone - this edge "
                            + "violates IEC 62443 zone/conduit segmentation and may "
                            + "indicate lateral movement or a misconfigured engineering station.")
                    .anomalyType(Anomaly.AnomalyType.PROTOCOL_VIOLATION)
                    .severity(sev)
                    .status(Anomaly.AnomalyStatus.DETECTED)
                    .sourceIp(first.getSourceIp())
                    .destinationIp(first.getDestinationIp())
                    .sourcePort(first.getSourcePort())
                    .destinationPort(first.getDestinationPort())
                    .protocol(first.getProtocol())
                    .purdueLevel("L" + dstLvl)
                    .evidence(evidence.toString())
                    .mitigationSteps("Investigate the originating host, revoke write access from that zone, and block the conduit at the firewall / data diode if not expected.")
                    .recommendations("Restrict Modbus / S7 write function codes to engineering stations inside the same zone. Enforce conduit allowlists on the OT firewall.")
                    .confidenceScore(0.85)
                    .riskScore(sev == Anomaly.AnomalySeverity.CRITICAL ? 90.0 : 75.0)
                    .mitreTactic("Impair Process Control")
                    .mitreTechnique("Unauthorized Command Message")
                    .mitreId("T0855")
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

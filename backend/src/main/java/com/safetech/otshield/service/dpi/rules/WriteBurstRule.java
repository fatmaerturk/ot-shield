package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.model.DpiEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Fires when a single source issues an abnormal burst of write PDUs to one
 * device in a capture - rapid, repeated parameter changes that look like
 * setpoint tampering, forced actuation, or a write-flood denial of service
 * rather than normal cyclic control.
 *
 * <p>MITRE ATT&amp;CK for ICS: {@code T0836 - Modify Parameter}.
 */
@Component
@Slf4j
public class WriteBurstRule implements DpiAnomalyRule {

    public static final String RULE_ID = "dpi.write_burst";
    public static final int BURST_THRESHOLD = 20; // write PDUs to one target in one capture

    @Override
    public String ruleId() { return RULE_ID; }

    @Override
    public List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx) {
        if (batch == null || batch.isEmpty()) return List.of();

        Map<String, List<DpiEvent>> writes = new HashMap<>();
        for (DpiEvent ev : batch) {
            if (!Boolean.TRUE.equals(ev.getIsWrite())) continue;
            if (ev.getSourceIp() == null || ev.getDestinationIp() == null) continue;
            writes.computeIfAbsent(ev.getSourceIp() + "|" + ev.getDestinationIp(), k -> new ArrayList<>()).add(ev);
        }

        List<AnomalyDTO> out = new ArrayList<>();
        for (Map.Entry<String, List<DpiEvent>> e : writes.entrySet()) {
            List<DpiEvent> evs = e.getValue();
            if (evs.size() < BURST_THRESHOLD) continue;
            DpiEvent f = evs.get(0);
            Set<String> regs = new HashSet<>();
            for (DpiEvent ev : evs) if (ev.getRegisterAddress() != null) regs.add(ev.getRegisterAddress());
            boolean severe = evs.size() >= BURST_THRESHOLD * 3;

            List<String> ind = new ArrayList<>(List.of("rule:" + RULE_ID,
                "source:" + f.getSourceIp(), "target:" + f.getDestinationIp(),
                "write_count:" + evs.size(), "distinct_registers:" + regs.size()));
            if (ctx.getPcapSessionId() != null) ind.add("pcap_session:" + ctx.getPcapSessionId());

            out.add(AnomalyDTO.builder()
                .title("Write burst: " + evs.size() + " writes from " + f.getSourceIp() + " to " + f.getDestinationIp())
                .description(f.getSourceIp() + " issued " + evs.size() + " " + safe(f.getProtocol())
                    + " write operations to " + f.getDestinationIp() + " across " + regs.size()
                    + " register(s) in a single capture. A rapid write burst is consistent with setpoint tampering, "
                    + "forced actuation, or a write-flood - not normal cyclic control.")
                .anomalyType(Anomaly.AnomalyType.VOLUME_ANOMALY)
                .severity(severe ? Anomaly.AnomalySeverity.HIGH : Anomaly.AnomalySeverity.MEDIUM)
                .status(Anomaly.AnomalyStatus.DETECTED)
                .sourceIp(f.getSourceIp()).destinationIp(f.getDestinationIp())
                .sourcePort(f.getSourcePort()).destinationPort(f.getDestinationPort())
                .protocol(f.getProtocol())
                .evidence(evs.size() + " write PDUs to " + f.getDestinationIp() + " over registers "
                    + (regs.isEmpty() ? "(unspecified)" : String.join(", ", capped(regs, 8))) + ".")
                .mitigationSteps("Correlate the burst against the change-control log. If unplanned, isolate the source and verify the device's current register/setpoint state against a known-good baseline.")
                .recommendations("Rate-limit writes per source at the OT firewall and alert when write volume to a control device exceeds its normal cyclic pattern.")
                .confidenceScore(severe ? 0.75 : 0.55).riskScore(severe ? 70.0 : 50.0)
                .mitreTactic("Impair Process Control").mitreTechnique("Modify Parameter").mitreId("T0836")
                .indicators(ind)
                .detectedAt(f.getEventTime() != null ? f.getEventTime() : LocalDateTime.now())
                .isActive(true).createdBy("dpi-engine")
                .build());
        }
        if (!out.isEmpty()) log.info("[{}] produced {} anomaly(ies)", RULE_ID, out.size());
        return out;
    }

    private static List<String> capped(Set<String> s, int n) {
        List<String> l = new ArrayList<>(s);
        return l.size() > n ? l.subList(0, n) : l;
    }

    private static String safe(String s) { return s == null ? "?" : s; }
}

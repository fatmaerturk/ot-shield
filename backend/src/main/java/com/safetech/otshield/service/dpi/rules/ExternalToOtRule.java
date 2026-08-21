package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.model.DpiEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Fires when a NON-private (Internet / external) source talks an ICS protocol to
 * an internal OT device. A public IP speaking Modbus/S7/IEC104 to a PLC means the
 * device is Internet-reachable or an intruder has pivoted inbound - one of the
 * highest-signal findings in OT.
 *
 * <p>MITRE ATT&amp;CK for ICS: {@code T0883 - Internet Accessible Device}.
 */
@Component
@Slf4j
public class ExternalToOtRule implements DpiAnomalyRule {

    public static final String RULE_ID = "dpi.external_to_ot";

    @Override
    public String ruleId() { return RULE_ID; }

    @Override
    public List<AnomalyDTO> evaluate(List<DpiEvent> batch, RuleContext ctx) {
        if (batch == null || batch.isEmpty()) return List.of();

        Map<String, List<DpiEvent>> groups = new HashMap<>();
        for (DpiEvent ev : batch) {
            String src = ev.getSourceIp(), dst = ev.getDestinationIp();
            if (src == null || dst == null) continue;
            boolean externalSrc = !isPrivate(src);
            boolean otDst = isPrivate(dst) || ctx.purdueLevelOf(dst) != null;
            if (!externalSrc || !otDst) continue;
            groups.computeIfAbsent(src + "|" + dst, k -> new ArrayList<>()).add(ev);
        }

        List<AnomalyDTO> out = new ArrayList<>();
        for (Map.Entry<String, List<DpiEvent>> e : groups.entrySet()) {
            List<DpiEvent> evs = e.getValue();
            DpiEvent f = evs.get(0);
            Integer lvl = ctx.purdueLevelOf(f.getDestinationIp());
            boolean critical = lvl != null && lvl <= 1;

            List<String> ind = new ArrayList<>(List.of("rule:" + RULE_ID,
                "external_source:" + f.getSourceIp(), "protocol:" + safe(f.getProtocol())));
            if (lvl != null) ind.add("dst_purdue:L" + lvl);
            if (ctx.getPcapSessionId() != null) ind.add("pcap_session:" + ctx.getPcapSessionId());

            out.add(AnomalyDTO.builder()
                .title("External host " + f.getSourceIp() + " speaks " + safe(f.getProtocol()) + " to OT device " + f.getDestinationIp())
                .description("A non-private (Internet-routable) source communicated an industrial protocol with an "
                    + "internal OT device. This indicates an Internet-exposed control device or an inbound intrusion, "
                    + "and should never happen on a properly segmented OT network.")
                .anomalyType(Anomaly.AnomalyType.ACCESS_PATTERN)
                .severity(critical ? Anomaly.AnomalySeverity.CRITICAL : Anomaly.AnomalySeverity.HIGH)
                .status(Anomaly.AnomalyStatus.DETECTED)
                .sourceIp(f.getSourceIp()).destinationIp(f.getDestinationIp())
                .sourcePort(f.getSourcePort()).destinationPort(f.getDestinationPort())
                .protocol(f.getProtocol())
                .evidence(evs.size() + " " + safe(f.getProtocol()) + " packet(s) from external " + f.getSourceIp()
                    + " to " + f.getDestinationIp() + (lvl != null ? " (Purdue L" + lvl + ")" : "") + ".")
                .mitigationSteps("Block the external source at the OT boundary firewall immediately and confirm no control device is directly Internet-exposed.")
                .recommendations("Enforce a deny-by-default OT perimeter; ICS protocols must never traverse the Internet boundary. Front any remote access with a broker in the DMZ.")
                .confidenceScore(0.85).riskScore(critical ? 90.0 : 75.0)
                .mitreTactic("Initial Access").mitreTechnique("Internet Accessible Device").mitreId("T0883")
                .indicators(ind)
                .detectedAt(f.getEventTime() != null ? f.getEventTime() : LocalDateTime.now())
                .isActive(true).createdBy("dpi-engine")
                .build());
        }
        if (!out.isEmpty()) log.info("[{}] produced {} anomaly(ies)", RULE_ID, out.size());
        return out;
    }

    private static boolean isPrivate(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) return true; // non-dotted-quad: don't flag
        try {
            int a = Integer.parseInt(p[0]), b = Integer.parseInt(p[1]);
            return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)
                || a == 127 || (a == 169 && b == 254);
        } catch (NumberFormatException ex) { return true; }
    }

    private static String safe(String s) { return s == null ? "?" : s; }
}

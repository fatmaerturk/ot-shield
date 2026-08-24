package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.AdaptationEventDTO;
import com.safetech.otshield.dto.decoy.DecoyActionRequest;
import com.safetech.otshield.dto.decoy.DecoyEnums;
import com.safetech.otshield.service.HoneytokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Closes the deception loop's weakest stage - ADAPT. When a breach is observed
 * (attacker writes to a decoy twin, or a honeytoken trips) this listener
 * automatically self-heals: it expands the decoy fabric for the targeted
 * protocol, flags the attacker for blocking at the OT boundary, and rotates in
 * a fresh honeytoken - then records the adaptation so the closed loop is
 * visible in the UI. Everything reuses real platform primitives
 * ({@link DecoyService#deployDecoy}, {@code applyAction(BLOCK_IP)},
 * {@link HoneytokenService#create}); nothing is faked.
 *
 * <p>Decoupled via {@link BreachDetectedEvent} so trigger sites don't create a
 * bean cycle. Adaptations are held in a bounded in-memory ring (like the twin
 * interaction log) - durable persistence can be added later.
 */
@Service
@Slf4j
public class DeceptionAdaptationService {

    private static final int MAX_EVENTS = 300;
    private static final long DEDUP_WINDOW_MS = 5 * 60 * 1000; // one adaptation per attacker+asset / 5 min

    private final DecoyService decoyService;
    private final HoneytokenService honeytokenService;

    private final Deque<AdaptationEventDTO> events = new ConcurrentLinkedDeque<>();
    private final Map<String, Long> lastAdaptedAt = new ConcurrentHashMap<>();
    private final AtomicLong seq = new AtomicLong();

    /** Decoy personas per protocol (reference data, not telemetry). */
    private static final Map<String, String[]> PERSONA = Map.of(
        "MODBUS", new String[]{"Schneider Electric", "Modicon M340", "502"},
        "S7", new String[]{"Siemens", "SIMATIC S7-1200", "102"},
        "S7COMM", new String[]{"Siemens", "SIMATIC S7-1200", "102"},
        "DNP3", new String[]{"GE Grid Solutions", "D20 RTU", "20000"},
        "ETHERNET_IP", new String[]{"Rockwell Automation", "ControlLogix 1756", "44818"},
        "IEC104", new String[]{"ABB", "RTU560", "2404"},
        "BACNET", new String[]{"Honeywell", "BACnet Controller", "47808"}
    );

    public DeceptionAdaptationService(DecoyService decoyService, HoneytokenService honeytokenService) {
        this.decoyService = decoyService;
        this.honeytokenService = honeytokenService;
    }

    @EventListener
    public void onBreach(BreachDetectedEvent e) {
        try {
            adapt(e);
        } catch (Exception ex) {
            log.warn("Adaptation failed for breach from {}: {}", e.getSourceIp(), ex.getMessage());
        }
    }

    /** Runs the self-healing actions; also callable directly (manual trigger). */
    public AdaptationEventDTO adapt(BreachDetectedEvent e) {
        String dedupKey = (e.getSourceIp() == null ? "?" : e.getSourceIp()) + "|"
                + (e.getAssetId() == null ? e.getProtocol() : e.getAssetId());
        long now = System.currentTimeMillis();
        Long last = lastAdaptedAt.get(dedupKey);
        if (last != null && now - last < DEDUP_WINDOW_MS) {
            log.debug("Skipping duplicate adaptation for {}", dedupKey);
            return null;
        }
        lastAdaptedAt.put(dedupKey, now);

        List<AdaptationEventDTO.Action> actions = new ArrayList<>();
        String proto = normalizeProtocol(e.getProtocol());

        // 1) EXPAND - ensure a decoy covers the targeted protocol
        try {
            String[] p = PERSONA.getOrDefault(proto, new String[]{"Generic OT", "PLC", "502"});
            boolean already = decoyService.isUserDeployed(proto);
            decoyService.deployDecoy(proto, p[0], p[1], Integer.valueOf(p[2]));
            actions.add(action("EXPAND_DECOY",
                    already ? proto + " decoy already covering this protocol - kept live"
                            : "Deployed a " + p[0] + " " + p[1] + " decoy for " + proto,
                    true));
        } catch (Exception ex) {
            actions.add(action("EXPAND_DECOY", "Could not expand decoy: " + ex.getMessage(), false));
        }

        // 2) BLOCK - flag the attacker at the OT boundary (platform block primitive)
        try {
            if (e.getSourceIp() != null && !e.getSourceIp().isBlank()) {
                DecoyActionRequest req = new DecoyActionRequest();
                req.setType(DecoyEnums.DecoyActionType.BLOCK_IP);
                req.setTargetIp(e.getSourceIp());
                req.setReason("Auto-adapt: breach (" + e.getTrigger() + ") from " + e.getSourceIp());
                decoyService.applyAction(req, "auto-adapt");
                actions.add(action("BLOCK_ATTACKER", "Flagged " + e.getSourceIp() + " for blocking at the OT boundary", true));
            } else {
                actions.add(action("BLOCK_ATTACKER", "No source IP to block", false));
            }
        } catch (Exception ex) {
            actions.add(action("BLOCK_ATTACKER", "Could not block: " + ex.getMessage(), false));
        }

        // 3) ROTATE - plant a fresh honeytoken lure toward the attacker
        try {
            String label = "Auto-lure after " + (e.getAssetName() != null ? e.getAssetName() : proto) + " breach";
            honeytokenService.create("URL_BEACON", label,
                    "Planted automatically in response to a breach from " + e.getSourceIp());
            actions.add(action("ROTATE_HONEYTOKEN", "Planted a fresh URL-beacon honeytoken (" + label + ")", true));
        } catch (Exception ex) {
            actions.add(action("ROTATE_HONEYTOKEN", "Could not plant honeytoken: " + ex.getMessage(), false));
        }

        AdaptationEventDTO ev = AdaptationEventDTO.builder()
                .id("adapt-" + seq.incrementAndGet())
                .ts(Instant.now())
                .trigger(e.getTrigger())
                .sourceIp(e.getSourceIp())
                .assetName(e.getAssetName())
                .protocol(proto)
                .summary(breachSummary(e))
                .actions(actions)
                .build();

        events.addFirst(ev);
        while (events.size() > MAX_EVENTS) events.pollLast();
        log.info("Deception adapted to breach from {} ({}): {} action(s)", e.getSourceIp(), e.getTrigger(), actions.size());
        return ev;
    }

    public List<AdaptationEventDTO> recent(int limit) {
        int n = Math.max(1, Math.min(limit, MAX_EVENTS));
        List<AdaptationEventDTO> out = new ArrayList<>(n);
        for (AdaptationEventDTO ev : events) {
            if (out.size() >= n) break;
            out.add(ev);
        }
        return out;
    }

    public Map<String, Object> stats() {
        int total = events.size();
        long decoys = countAction("EXPAND_DECOY");
        long blocks = countAction("BLOCK_ATTACKER");
        long tokens = countAction("ROTATE_HONEYTOKEN");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("totalAdaptations", total);
        m.put("decoysExpanded", decoys);
        m.put("attackersBlocked", blocks);
        m.put("honeytokensPlanted", tokens);
        return m;
    }

    private long countAction(String type) {
        return events.stream()
                .flatMap(e -> e.getActions().stream())
                .filter(a -> type.equals(a.getType()) && a.isSuccess())
                .count();
    }

    private AdaptationEventDTO.Action action(String type, String detail, boolean ok) {
        return AdaptationEventDTO.Action.builder().type(type).detail(detail).success(ok).build();
    }

    private String breachSummary(BreachDetectedEvent e) {
        if ("HONEYTOKEN_TRIP".equals(e.getTrigger())) {
            return "Honeytoken tripped by " + e.getSourceIp() + (e.getDetail() != null ? " (" + e.getDetail() + ")" : "");
        }
        return (e.getDetail() != null ? e.getDetail() + " " : "Write ") + "against decoy twin of "
                + (e.getAssetName() != null ? e.getAssetName() : e.getProtocol()) + " from " + e.getSourceIp();
    }

    private String normalizeProtocol(String p) {
        if (p == null || p.isBlank()) return "MODBUS";
        return p.trim().toUpperCase().replace("/TCP", "").replace(" ", "");
    }
}

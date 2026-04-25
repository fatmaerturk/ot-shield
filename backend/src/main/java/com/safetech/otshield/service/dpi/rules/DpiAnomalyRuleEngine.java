package com.safetech.otshield.service.dpi.rules;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.model.DpiEvent;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.DpiEventRepository;
import com.safetech.otshield.service.AnomalyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Orchestrates all {@link DpiAnomalyRule} beans over a single pcap upload's
 * batch of DPI events. Lives in {@code service.dpi.rules} so it is wired up
 * automatically via Spring's component scan.
 *
 * <p>Lifecycle for one pcap:
 * <ol>
 *   <li>{@link com.safetech.otshield.service.PcapAnalysisService} persists the
 *       batch of {@link DpiEvent} rows.</li>
 *   <li>{@link #evaluateAndPersist(List, String)} is called with the same
 *       list; it builds a {@link RuleContext} (IP → Purdue level map +
 *       historical function-code histogram) and runs every registered rule
 *       against the batch.</li>
 *   <li>Anomalies are deduplicated on {@code (ruleId, sourceIp, destinationIp,
 *       functionCodeIndicator)} - so re-running the same pcap (or two
 *       concurrent pcaps containing the same attack) produces a single row
 *       per attack in the DB.</li>
 *   <li>Each unique anomaly is saved via {@link AnomalyService#createAnomaly}.</li>
 * </ol>
 *
 * <p>Failures inside the engine must <b>not</b> fail the pcap upload - we
 * log-and-swallow so the user still gets their traffic ingested even if rule
 * evaluation is broken.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DpiAnomalyRuleEngine {

    private final List<DpiAnomalyRule> rules;
    private final AssetRepository assetRepository;
    private final DpiEventRepository dpiEventRepository;
    private final AnomalyService anomalyService;

    /**
     * Run all registered rules against this batch and persist any new
     * anomalies. Safe to call with {@code null} or empty batches.
     *
     * @return number of anomalies actually persisted (after dedup).
     */
    public int evaluateAndPersist(List<DpiEvent> batch, String pcapSessionId) {
        if (batch == null || batch.isEmpty()) {
            log.debug("DPI anomaly engine: empty batch for session {}, skipping", pcapSessionId);
            return 0;
        }
        if (rules == null || rules.isEmpty()) {
            log.warn("DPI anomaly engine: no rules registered, skipping");
            return 0;
        }

        RuleContext ctx;
        try {
            ctx = buildContext(pcapSessionId);
        } catch (Exception ex) {
            log.warn("Failed to build DPI rule context: {}", ex.getMessage());
            return 0;
        }

        // Collect across all rules, then dedupe.
        List<AnomalyDTO> produced = new ArrayList<>();
        for (DpiAnomalyRule rule : rules) {
            try {
                List<AnomalyDTO> emitted = rule.evaluate(batch, ctx);
                if (emitted != null && !emitted.isEmpty()) {
                    produced.addAll(emitted);
                }
            } catch (Exception ex) {
                // One broken rule must not take down the whole pipeline.
                log.warn("DPI rule {} threw while evaluating: {}", rule.ruleId(), ex.getMessage());
            }
        }

        if (produced.isEmpty()) {
            log.info("DPI anomaly engine: {} event(s) evaluated for session {}, no anomalies", batch.size(), pcapSessionId);
            return 0;
        }

        // Dedupe across rules - two rules could match the same conduit with
        // the same function code; we keep the first (highest-priority rule
        // order == discovery order in the Spring component list, but that's
        // fine for now).
        Set<String> seen = new HashSet<>();
        int persisted = 0;
        for (AnomalyDTO dto : produced) {
            String key = dedupKey(dto);
            if (!seen.add(key)) continue;
            try {
                anomalyService.createAnomaly(dto);
                persisted++;
            } catch (Exception ex) {
                log.warn("Could not persist DPI anomaly ({}): {}", dto.getTitle(), ex.getMessage());
            }
        }

        log.info("DPI anomaly engine: session {} produced {} raw / {} persisted anomalies from {} events",
                pcapSessionId, produced.size(), persisted, batch.size());
        return persisted;
    }

    /**
     * Build the context that rules share. Performed <b>after</b> the batch has
     * been saved so {@link RareFunctionCodeRule} can ask the DB for a "baseline
     * excluding this session" histogram without double-counting.
     */
    private RuleContext buildContext(String pcapSessionId) {
        Map<String, Integer> ipToLevel = new HashMap<>();
        for (Asset a : assetRepository.findAll()) {
            if (a.getIpAddress() == null || a.getPurdueLevel() == null) continue;
            Integer level = toNumeric(a.getPurdueLevel());
            if (level != null) ipToLevel.put(a.getIpAddress(), level);
        }

        Map<String, Long> histogram = new HashMap<>();
        try {
            List<Object[]> rows = dpiEventRepository
                    .globalFunctionCodeHistogramExcludingSession(pcapSessionId);
            for (Object[] row : rows) {
                String protocol = row[0] != null ? row[0].toString() : null;
                String fc = row[1] != null ? row[1].toString() : null;
                Long count = row[2] != null ? ((Number) row[2]).longValue() : 0L;
                histogram.put(RuleContext.fcKey(protocol, fc), count);
            }
        } catch (Exception ex) {
            log.debug("Could not load function-code histogram: {}", ex.getMessage());
        }

        return new RuleContext(ipToLevel, histogram, pcapSessionId);
    }

    /**
     * Map Asset.PurdueLevel enum names (LEVEL_0..LEVEL_5) to numeric 0..5.
     * Returns null for anything unexpected so the caller can skip the asset.
     */
    private static Integer toNumeric(Asset.PurdueLevel level) {
        if (level == null) return null;
        String name = level.name(); // "LEVEL_3"
        int idx = name.lastIndexOf('_');
        if (idx < 0 || idx + 1 >= name.length()) return null;
        try {
            return Integer.parseInt(name.substring(idx + 1));
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    /**
     * Produce a stable dedup key for an anomaly. Ties together all factors
     * that distinguish "truly different" anomalies in a single pcap:
     * <ul>
     *   <li>rule indicator (every rule injects its id)</li>
     *   <li>source / destination IP</li>
     *   <li>function_code indicator (if present) - so a rare-fc alert for FC 0x06
     *       and one for FC 0x05 on the same conduit don't collapse.</li>
     * </ul>
     */
    private static String dedupKey(AnomalyDTO dto) {
        String rule = "?";
        String fc = "";
        if (dto.getIndicators() != null) {
            for (String ind : dto.getIndicators()) {
                if (ind == null) continue;
                if (ind.startsWith("rule:")) rule = ind.substring(5);
                else if (ind.startsWith("function_code:")) fc = ind.substring("function_code:".length());
            }
        }
        return rule + "|" + String.valueOf(dto.getSourceIp()) + "->" + String.valueOf(dto.getDestinationIp())
                + (fc.isEmpty() ? "" : ("|fc=" + fc));
    }
}

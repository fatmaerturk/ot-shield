package com.safetech.otshield.service.dpi.rules;

import java.util.Collections;
import java.util.Map;

/**
 * Read-only bundle of reference data that {@link DpiAnomalyRule} implementations
 * need to make their decision. Created once per batch (one pcap upload) inside
 * {@link DpiAnomalyRuleEngine#evaluate} so individual rules don't each hammer
 * the DB.
 *
 * <ul>
 *   <li>{@code ipToPurdueLevel} - IP address → Purdue level (0..5). Used by the
 *       unauthorized-write rule to detect edges that cross a zone boundary.
 *       IPs that are not known assets are absent from the map.</li>
 *   <li>{@code globalFunctionCodeCounts} - {@code protocol + "::" + functionCode}
 *       → historical occurrence count. Drives the "rare function code" rule's
 *       first-seen detection.</li>
 *   <li>{@code pcapSessionId} - session id that should be embedded in the
 *       generated anomaly's {@code customFields}/{@code indicators} for
 *       replay/cleanup.</li>
 * </ul>
 */
public final class RuleContext {

    private final Map<String, Integer> ipToPurdueLevel;
    private final Map<String, Long> globalFunctionCodeCounts;
    private final String pcapSessionId;

    public RuleContext(Map<String, Integer> ipToPurdueLevel,
                       Map<String, Long> globalFunctionCodeCounts,
                       String pcapSessionId) {
        this.ipToPurdueLevel = ipToPurdueLevel != null
                ? Collections.unmodifiableMap(ipToPurdueLevel)
                : Collections.emptyMap();
        this.globalFunctionCodeCounts = globalFunctionCodeCounts != null
                ? Collections.unmodifiableMap(globalFunctionCodeCounts)
                : Collections.emptyMap();
        this.pcapSessionId = pcapSessionId;
    }

    public Map<String, Integer> getIpToPurdueLevel() {
        return ipToPurdueLevel;
    }

    public Map<String, Long> getGlobalFunctionCodeCounts() {
        return globalFunctionCodeCounts;
    }

    public String getPcapSessionId() {
        return pcapSessionId;
    }

    /**
     * Look up the Purdue level of an IP, or {@code null} when the IP is not a
     * known asset. Callers should treat unknown IPs as "outside the plant
     * topology" rather than L0.
     */
    public Integer purdueLevelOf(String ip) {
        if (ip == null) return null;
        return ipToPurdueLevel.get(ip);
    }

    /**
     * Canonical key for the global function-code histogram.
     */
    public static String fcKey(String protocol, String functionCode) {
        return (protocol == null ? "?" : protocol) + "::" + (functionCode == null ? "?" : functionCode);
    }
}

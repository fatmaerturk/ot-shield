package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.DecoyInstanceDTO;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.DpiEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Predictive decoy placement. Builds an attack graph from the REAL asset
 * inventory (Purdue levels) and observed DPI connections, then for each
 * crown-jewel asset computes the shortest path an attacker would traverse to
 * reach it and the choke-point where a decoy would break that path. This turns
 * deception from reactive to predictive: "place a decoy HERE because that is
 * where the attacker will go next." All graph data is real; nothing is faked.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AttackPathService {

    private final AssetRepository assetRepository;
    private final DpiEventRepository dpiEventRepository;
    private final DecoyService decoyService;

    @Transactional(readOnly = true)
    public Map<String, Object> buildAttackPaths() {
        List<Asset> assets = new ArrayList<>();
        try { assets = assetRepository.findAll(); } catch (Exception ignore) {}
        Map<String, Asset> byIp = new LinkedHashMap<>();
        for (Asset a : assets) {
            if (a.getIpAddress() != null && !a.getIpAddress().isBlank()) byIp.put(a.getIpAddress(), a);
        }

        // Which protocols are already covered by a live decoy (asset "mirrored").
        Set<String> deployedProtocols = new HashSet<>();
        try {
            for (DecoyInstanceDTO d : decoyService.listInstances()) {
                if (d.getProtocol() != null) deployedProtocols.add(d.getProtocol().name().toUpperCase());
            }
        } catch (Exception ignore) {}

        // --- Build undirected edges: observed DPI connections (real) + Purdue-
        //     adjacent assets in the same /24 (inferred lateral reachability) ---
        Map<String, Set<String>> adj = new HashMap<>();
        Set<String> observedPairs = new HashSet<>();
        try {
            for (Object[] row : dpiEventRepository.observedConnections(null, null)) {
                String s = (String) row[0], d = (String) row[1];
                if (s == null || d == null || s.equals(d)) continue;
                if (byIp.containsKey(s) && byIp.containsKey(d)) {
                    link(adj, s, d);
                    observedPairs.add(edgeKey(s, d));
                }
            }
        } catch (Exception ignore) {}

        List<String> ips = new ArrayList<>(byIp.keySet());
        for (int i = 0; i < ips.size(); i++) {
            for (int j = i + 1; j < ips.size(); j++) {
                Asset a = byIp.get(ips.get(i)), b = byIp.get(ips.get(j));
                int la = purdueNum(a), lb = purdueNum(b);
                if (la < 0 || lb < 0) continue;
                if (Math.abs(la - lb) == 1 && sameSubnet(a.getIpAddress(), b.getIpAddress())) {
                    link(adj, a.getIpAddress(), b.getIpAddress()); // inferred Purdue-descent edge
                }
            }
        }

        // Crown jewels: deepest Purdue (Level 0/1) or CRITICAL/HIGH criticality.
        List<Asset> jewels = new ArrayList<>();
        for (Asset a : byIp.values()) {
            int p = purdueNum(a);
            boolean deep = p == 0 || p == 1;
            boolean crit = a.getCriticalityLevel() == Asset.CriticalityLevel.CRITICAL
                        || a.getCriticalityLevel() == Asset.CriticalityLevel.HIGH;
            if (deep || crit) jewels.add(a);
        }
        jewels.sort(Comparator.comparingInt((Asset a) -> -valueScore(a)));

        // Entry points: the highest Purdue level present (closest to untrusted side).
        int maxLevel = byIp.values().stream().map(this::purdueNum).filter(n -> n >= 0).max(Integer::compareTo).orElse(-1);
        List<String> entries = new ArrayList<>();
        for (Asset a : byIp.values()) if (purdueNum(a) == maxLevel && !isJewel(a)) entries.add(a.getIpAddress());
        if (entries.isEmpty()) entries.addAll(byIp.keySet()); // fallback: any asset can be the landing point

        // --- For each jewel, shortest path from the nearest entry ---
        List<Map<String, Object>> paths = new ArrayList<>();
        Map<String, Integer> chokeFrequency = new HashMap<>();
        int unreachable = 0;

        for (Asset jewel : jewels) {
            List<String> best = null;
            String bestEntry = null;
            for (String entry : entries) {
                if (entry.equals(jewel.getIpAddress())) continue;
                List<String> path = bfs(adj, entry, jewel.getIpAddress());
                if (path != null && (best == null || path.size() < best.size())) { best = path; bestEntry = entry; }
            }
            if (best == null) { unreachable++; continue; }

            // Chokepoint = highest-value intermediate node not already mirrored.
            String choke = null;
            int chokeVal = Integer.MIN_VALUE;
            for (int k = 1; k < best.size() - 1; k++) {
                String ip = best.get(k);
                Asset mid = byIp.get(ip);
                if (mid == null) continue;
                boolean mirrored = isMirrored(mid, deployedProtocols);
                int score = valueScore(mid) + (mirrored ? -100 : 0); // prefer unmirrored
                if (score > chokeVal) { chokeVal = score; choke = ip; }
                chokeFrequency.merge(ip, 1, Integer::sum);
            }

            List<Map<String, Object>> hopNodes = new ArrayList<>();
            for (String ip : best) hopNodes.add(node(byIp.get(ip), ip, deployedProtocols));

            Map<String, Object> p = new LinkedHashMap<>();
            p.put("fromIp", bestEntry);
            p.put("fromName", nameOf(byIp.get(bestEntry), bestEntry));
            p.put("toIp", jewel.getIpAddress());
            p.put("toName", nameOf(jewel, jewel.getIpAddress()));
            p.put("hops", best.size() - 1);
            p.put("path", hopNodes);
            if (choke != null) {
                Asset c = byIp.get(choke);
                p.put("chokepoint", node(c, choke, deployedProtocols));
                p.put("recommendation", isMirrored(c, deployedProtocols)
                        ? "Choke-point already mirrored - the path is covered."
                        : "Place a " + safeProto(c) + " decoy at " + nameOf(c, choke) + " to break this path before the crown jewel.");
            } else {
                p.put("chokepoint", null);
                p.put("recommendation", "Direct edge - mirror the crown jewel itself with a twin decoy.");
            }
            paths.add(p);
        }

        // Top placement recommendations: intermediates on the most paths, unmirrored first.
        List<Map<String, Object>> topRecs = new ArrayList<>();
        chokeFrequency.entrySet().stream()
                .sorted((x, y) -> Integer.compare(y.getValue(), x.getValue()))
                .limit(5)
                .forEach(e -> {
                    Asset a = byIp.get(e.getKey());
                    if (a == null) return;
                    boolean mirrored = isMirrored(a, deployedProtocols);
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("ip", e.getKey());
                    r.put("name", nameOf(a, e.getKey()));
                    r.put("protocol", safeProto(a));
                    r.put("onPaths", e.getValue());
                    r.put("mirrored", mirrored);
                    r.put("purdueLevel", a.getPurdueLevel() != null ? a.getPurdueLevel().name() : null);
                    r.put("rationale", "Sits on " + e.getValue() + " attack path(s) to a crown jewel"
                            + (mirrored ? " - already mirrored." : " - deploying a decoy here breaks them."));
                    topRecs.add(r);
                });

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("assetCount", byIp.size());
        summary.put("crownJewelCount", jewels.size());
        summary.put("observedEdges", observedPairs.size());
        summary.put("pathsFound", paths.size());
        summary.put("unreachableJewels", unreachable);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("summary", summary);
        out.put("crownJewels", jewels.stream().map(a -> node(a, a.getIpAddress(), deployedProtocols)).toList());
        out.put("entryPoints", entries.stream().map(ip -> node(byIp.get(ip), ip, deployedProtocols)).toList());
        out.put("paths", paths);
        out.put("topRecommendations", topRecs);
        return out;
    }

    // ------------------------------------------------------------------
    // Graph helpers
    // ------------------------------------------------------------------

    private void link(Map<String, Set<String>> adj, String a, String b) {
        adj.computeIfAbsent(a, k -> new LinkedHashSet<>()).add(b);
        adj.computeIfAbsent(b, k -> new LinkedHashSet<>()).add(a);
    }

    private List<String> bfs(Map<String, Set<String>> adj, String start, String goal) {
        if (start.equals(goal)) return List.of(start);
        Queue<String> q = new ArrayDeque<>();
        Map<String, String> prev = new HashMap<>();
        Set<String> seen = new HashSet<>();
        q.add(start); seen.add(start);
        while (!q.isEmpty()) {
            String cur = q.poll();
            for (String nb : adj.getOrDefault(cur, Set.of())) {
                if (seen.add(nb)) {
                    prev.put(nb, cur);
                    if (nb.equals(goal)) {
                        LinkedList<String> path = new LinkedList<>();
                        for (String at = goal; at != null; at = prev.get(at)) path.addFirst(at);
                        return path;
                    }
                    q.add(nb);
                }
            }
        }
        return null;
    }

    private Map<String, Object> node(Asset a, String ip, Set<String> deployedProtocols) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ip", ip);
        m.put("name", nameOf(a, ip));
        m.put("purdueLevel", a != null && a.getPurdueLevel() != null ? a.getPurdueLevel().name() : null);
        m.put("criticality", a != null && a.getCriticalityLevel() != null ? a.getCriticalityLevel().name() : null);
        m.put("protocol", safeProto(a));
        m.put("mirrored", isMirrored(a, deployedProtocols));
        return m;
    }

    private boolean isMirrored(Asset a, Set<String> deployedProtocols) {
        if (a == null || a.getProtocol() == null) return false;
        return deployedProtocols.contains(a.getProtocol().toUpperCase());
    }

    private boolean isJewel(Asset a) {
        int p = purdueNum(a);
        return p == 0 || p == 1
            || a.getCriticalityLevel() == Asset.CriticalityLevel.CRITICAL
            || a.getCriticalityLevel() == Asset.CriticalityLevel.HIGH;
    }

    private int valueScore(Asset a) {
        int p = purdueNum(a);
        int purdueVal = p < 0 ? 0 : (5 - p) * 10; // deeper (lower level) = higher value
        int critVal = 0;
        if (a.getCriticalityLevel() != null) {
            switch (a.getCriticalityLevel()) {
                case CRITICAL: critVal = 40; break;
                case HIGH: critVal = 25; break;
                case MEDIUM: critVal = 10; break;
                default: critVal = 0;
            }
        }
        return purdueVal + critVal;
    }

    private int purdueNum(Asset a) {
        if (a == null || a.getPurdueLevel() == null) return -1;
        String n = a.getPurdueLevel().name(); // LEVEL_3
        int us = n.lastIndexOf('_');
        try { return Integer.parseInt(n.substring(us + 1)); } catch (Exception e) { return -1; }
    }

    private boolean sameSubnet(String a, String b) {
        if (a == null || b == null) return false;
        return threeOctets(a).equals(threeOctets(b));
    }

    private String threeOctets(String ip) {
        int i = ip.lastIndexOf('.');
        return i > 0 ? ip.substring(0, i) : ip;
    }

    private String nameOf(Asset a, String ip) {
        if (a == null) return ip;
        return a.getName() != null && !a.getName().isBlank() ? a.getName() : ip;
    }

    private String safeProto(Asset a) {
        return a != null && a.getProtocol() != null ? a.getProtocol() : "OT";
    }

    private String edgeKey(String a, String b) {
        return a.compareTo(b) < 0 ? a + "|" + b : b + "|" + a;
    }
}

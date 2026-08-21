package com.safetech.otshield.service;

import com.safetech.otshield.model.Asset;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.DpiEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Passive asset discovery from real captured traffic.
 *
 * Instead of a hand-maintained inventory, every device seen speaking an ICS
 * protocol on the wire (from the DPI/pcap dissector) becomes an asset: its IP,
 * the protocol it actually speaks, its role (master/initiator vs field/responder
 * inferred from traffic direction), a Purdue level, and first/last-seen - all
 * first-party, nothing fabricated. This is how real OT monitoring builds an
 * inventory (Dragos/Claroty do the same) and it keeps the asset list honest:
 * it contains exactly what is on the network, so downstream views (OT activity,
 * deception coverage, alerts) line up with the traffic.
 *
 * Idempotent: assets are upserted by IP, so re-runs enrich rather than duplicate.
 */
// DISABLED (@Service removed so it is not a Spring bean and never runs). The
// richer upload-time discovery in PcapAnalysisService.detectAndSaveAssets (real
// OUI vendor + CDP/LLDP model from raw packets) is the single source of truth
// for the inventory. This dpi_events-based fallback is kept for reference / a
// future live-capture path, but is inert to avoid duplicate, poorer-quality
// (Unknown-vendor) assets competing with the upload-time discovery.
@Slf4j
@RequiredArgsConstructor
public class AssetDiscoveryService {

    private final DpiEventRepository dpiRepo;
    private final AssetRepository assetRepo;

    private static final int MAX_DEVICES = 100; // safety cap

    private static class Dev {
        final String ip;
        long asSource;
        long asDest;
        final Map<String, Long> protoCounts = new HashMap<>();
        LocalDateTime first;
        LocalDateTime last;
        Dev(String ip) { this.ip = ip; }
        long total() { return asSource + asDest; }
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        discover();
    }

    @Scheduled(fixedDelay = 600000, initialDelay = 30000)
    public void scheduled() {
        discover();
    }

    @Transactional
    public void discover() {
        Map<String, Dev> devices = new HashMap<>();
        try {
            for (Object[] r : dpiRepo.deviceStatsAsDestination()) accumulate(devices, r, false);
            for (Object[] r : dpiRepo.deviceStatsAsSource()) accumulate(devices, r, true);
        } catch (Exception e) {
            log.warn("AssetDiscovery: telemetry aggregation failed: {}", e.getMessage());
            return;
        }

        List<Dev> ranked = devices.values().stream()
            .filter(d -> looksLikeDevice(d.ip))
            .sorted((x, y) -> Long.compare(y.total(), x.total()))
            .limit(MAX_DEVICES)
            .toList();

        int created = 0, updated = 0;
        for (Dev d : ranked) {
            try {
                if (upsert(d)) created++; else updated++;
            } catch (Exception e) {
                log.warn("AssetDiscovery: upsert failed for {}: {}", d.ip, e.getMessage());
            }
        }
        if (created > 0) log.info("AssetDiscovery: discovered {} new asset(s) from traffic ({} updated)", created, updated);
    }

    private void accumulate(Map<String, Dev> devices, Object[] r, boolean asSource) {
        String ip = (String) r[0];
        String proto = (String) r[1];
        long cnt = ((Number) r[2]).longValue();
        LocalDateTime first = (LocalDateTime) r[3];
        LocalDateTime last = (LocalDateTime) r[4];
        if (ip == null || ip.isBlank()) return;

        Dev d = devices.computeIfAbsent(ip, Dev::new);
        if (asSource) d.asSource += cnt; else d.asDest += cnt;
        if (proto != null && !proto.isBlank()) d.protoCounts.merge(canon(proto), cnt, Long::sum);
        if (first != null && (d.first == null || first.isBefore(d.first))) d.first = first;
        if (last != null && (d.last == null || last.isAfter(d.last))) d.last = last;
    }

    /** Create or update the asset for a discovered device. Returns true if created. */
    private boolean upsert(Dev d) {
        String proto = d.protoCounts.entrySet().stream()
            .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse("ICS");

        // Direction heuristic: mostly a responder -> field device (slave); mostly
        // an initiator -> supervisory master.
        boolean fieldDevice = d.asDest >= d.asSource;
        Asset.AssetType type = fieldDevice ? Asset.AssetType.PLC : Asset.AssetType.SCADA;
        Asset.PurdueLevel purdue = fieldDevice ? Asset.PurdueLevel.LEVEL_1 : Asset.PurdueLevel.LEVEL_2;
        String lastOctet = d.ip.contains(".") ? d.ip.substring(d.ip.lastIndexOf('.') + 1) : d.ip;
        String name = proto + "-" + (fieldDevice ? "field" : "master") + "-" + lastOctet;

        Asset existing = assetRepo.findByIpAddress(d.ip).orElse(null);
        boolean created = existing == null;
        Asset a = created ? new Asset() : existing;

        if (created) {
            a.setId("disc-" + d.ip.replaceAll("[^0-9A-Za-z]", "-"));
            a.setName(name);
            a.setAssetType(type);
            a.setPurdueLevel(purdue);
            a.setManufacturer("Unknown (passive discovery)");
            a.setModel(proto + " device");
            a.setAssetCategory(Asset.AssetCategory.CONTROL_SYSTEM);
            a.setFirstSeen(d.first);
        }
        // Always refresh the observed facts.
        a.setIpAddress(d.ip);
        a.setProtocol(proto);
        a.setDescription("Auto-discovered from network traffic - speaks " + proto
            + " (" + d.total() + " observed interactions, "
            + (fieldDevice ? "responder/field device" : "initiator/master") + ").");
        a.setLastSeen(d.last);
        try { a.setIsActive(true); } catch (Exception ignored) { }
        try { a.setIsOnline(true); } catch (Exception ignored) { }

        assetRepo.save(a);
        return created;
    }

    /** Skip non-host addresses (broadcast, multicast, loopback, all-zeros). */
    private static boolean looksLikeDevice(String ip) {
        if (ip == null || ip.isBlank()) return false;
        if (ip.equals("0.0.0.0") || ip.equals("255.255.255.255")) return false;
        if (ip.startsWith("127.") || ip.startsWith("169.254.")) return false;
        if (ip.startsWith("224.") || ip.startsWith("239.") || ip.endsWith(".255")) return false;
        return ip.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    }

    /** Normalise raw protocol strings onto canonical ICS keys. */
    private static String canon(String p) {
        if (p == null) return "ICS";
        String u = p.toUpperCase();
        switch (u) {
            case "S7COMM": return "S7";
            case "ENIP": case "ETHERNETIP": case "ETHERNET/IP": return "ETHERNET_IP";
            case "IEC-104": case "IEC 104": return "IEC104";
            default: return u;
        }
    }
}

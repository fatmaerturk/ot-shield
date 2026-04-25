package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.InventoryItem;
import com.safetech.otshield.model.research.InventoryItem.Kind;
import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.model.research.ResearchDocument.IngestStatus;
import com.safetech.otshield.model.research.ResearchDocumentChunk;
import com.safetech.otshield.repository.research.InventoryItemRepository;
import com.safetech.otshield.repository.research.ResearchDocumentChunkRepository;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, regex-based extractor that scans a bundle's READY
 * documents and populates {@link InventoryItem} rows for any
 * {@link Kind#PORT}, {@link Kind#PROTOCOL} or {@link Kind#SERVICE}
 * it can confidently identify.
 *
 * <p>Design decisions aligned with the HMGCC brief:
 *
 * <ul>
 *   <li><b>No LLM inference here.</b> Rule-based extraction is fast
 *       (milliseconds), runs fully offline, and never hallucinates a
 *       port or protocol the source text doesn't mention.</li>
 *   <li><b>Every row records its source.</b> The {@code source} column
 *       is written as {@code doc:{id}#chunk:{n}} so a researcher can
 *       click back to the passage that produced the entry.</li>
 *   <li><b>Idempotent.</b> Re-running the extractor is safe. We skip
 *       items whose {@code (kind, lowercase name)} is already present
 *       in the bundle, so the table grows monotonically without
 *       duplication.</li>
 *   <li><b>Conservative.</b> The pattern set errs on the side of
 *       precision: we'd rather miss a mention than invent one. A
 *       future LLM-driven deep-extract pass will fill the long tail.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InventoryExtractor {

    private final ResearchDocumentRepository documentRepo;
    private final ResearchDocumentChunkRepository chunkRepo;
    private final InventoryItemRepository inventoryRepo;

    /**
     * Well-known ICS/OT + IT protocols we recognise by name. Each
     * entry is a human-readable label paired with a case-insensitive
     * regex that matches common spellings in vendor manuals and
     * datasheets.
     */
    private static final List<NamedPattern> PROTOCOL_PATTERNS = List.of(
            np("Modbus TCP",    "(?i)\\bmodbus[-\\s]*(?:tcp|/ip)\\b"),
            np("Modbus RTU",    "(?i)\\bmodbus[-\\s]*rtu\\b"),
            np("Modbus ASCII",  "(?i)\\bmodbus[-\\s]*ascii\\b"),
            np("Modbus",        "(?i)\\bmodbus\\b"),
            np("S7Comm",        "(?i)\\b(s7[-\\s]*comm|s7comm|isoontcp\\s*s7)\\b"),
            np("DNP3",          "(?i)\\bdnp[-\\s]*3\\b"),
            np("IEC 60870-5-104", "(?i)\\biec[-\\s]*60870[-\\s]*5[-\\s]*104\\b|\\biec\\s*104\\b"),
            np("IEC 60870-5-101", "(?i)\\biec[-\\s]*60870[-\\s]*5[-\\s]*101\\b"),
            np("IEC 61850",     "(?i)\\biec[-\\s]*61850\\b"),
            np("EtherNet/IP",   "(?i)\\bethernet[-/\\s]*ip\\b|\\benip\\b"),
            np("Profinet",      "(?i)\\bprofi[-\\s]*net\\b"),
            np("Profibus",      "(?i)\\bprofi[-\\s]*bus\\b"),
            np("BACnet",        "(?i)\\bbacnet\\b"),
            np("OPC UA",        "(?i)\\bopc[-\\s]*ua\\b"),
            np("OPC DA",        "(?i)\\bopc[-\\s]*da\\b"),
            np("CAN bus",       "(?i)\\bcan[-\\s]*bus\\b|\\bcanopen\\b"),
            np("MQTT",          "(?i)\\bmqtt\\b"),
            np("CoAP",          "(?i)\\bcoap\\b"),
            np("HART",          "(?i)\\bhart\\s+(?:protocol|comm)\\b|\\bhart-?ip\\b"),
            np("HTTP",          "(?i)\\bhttp/?1\\.[01]\\b|\\bhttp\\b"),
            np("HTTPS",         "(?i)\\bhttps\\b|\\btls\\s*1\\.[0-3]\\b"),
            np("FTP",           "(?i)\\bftp\\b"),
            np("SFTP",          "(?i)\\bsftp\\b"),
            np("TFTP",          "(?i)\\btftp\\b"),
            np("SSH",           "(?i)\\bssh\\b"),
            np("Telnet",        "(?i)\\btelnet\\b"),
            np("SNMP",          "(?i)\\bsnmp\\s*v?[123]?\\b"),
            np("SMB",           "(?i)\\bsmb\\s*v?[123]?\\b|\\bcifs\\b"),
            np("RDP",           "(?i)\\brdp\\b|\\bremote\\s+desktop\\s+protocol\\b"),
            np("VNC",           "(?i)\\bvnc\\b"),
            np("Syslog",        "(?i)\\bsyslog\\b"),
            np("NTP",           "(?i)\\bntp\\b|\\bnetwork\\s+time\\s+protocol\\b"),
            np("DHCP",          "(?i)\\bdhcp\\b"),
            np("DNS",           "(?i)\\bdns\\b(?!\\s*[-/])")
    );

    /**
     * Common service keywords that show up in OT manuals. Matching on
     * these gives the researcher a head-start on the Services list.
     */
    private static final List<NamedPattern> SERVICE_PATTERNS = List.of(
            np("Web UI",               "(?i)\\b(web\\s*ui|web\\s*interface|web[-\\s]*based\\s*management)\\b"),
            np("Admin portal",         "(?i)\\badmin(?:istration)?\\s+(?:portal|page|console)\\b"),
            np("Engineering station",  "(?i)\\bengineering\\s+(?:station|workstation)\\b"),
            np("HMI",                  "(?i)\\bhuman[-\\s]*machine\\s+interface\\b|\\bhmi\\b"),
            np("SCADA",                "(?i)\\bscada\\b"),
            np("OPC server",           "(?i)\\bopc\\s+server\\b"),
            np("Firmware update",      "(?i)\\bfirmware\\s+(?:update|upgrade)\\b"),
            np("TLS server",           "(?i)\\btls\\s+server\\b|\\bssl\\s+listener\\b"),
            np("SSH server",           "(?i)\\bssh[d]?\\s+(?:server|daemon|service)\\b"),
            np("Web server",           "(?i)\\b(apache|nginx|lighttpd|iis|boa|mini[-\\s]*httpd)\\b")
    );

    /**
     * Matches numeric port references. Captures the number so we can
     * tag the inventory row as "Port N/TCP".
     */
    private static final Pattern PORT_PATTERN = Pattern.compile(
            "(?i)\\b(?:port\\s+)?(\\d{2,5})\\s*/\\s*(tcp|udp)\\b");

    /**
     * A second port shape: "TCP port 502", "UDP port 4840". Same idea,
     * different word order - worth catching because datasheets use
     * both.
     */
    private static final Pattern PORT_WORD_PATTERN = Pattern.compile(
            "(?i)\\b(tcp|udp)\\s+port\\s+(\\d{2,5})\\b");

    // ---- Public entry point -------------------------------------------

    /**
     * Regex-scan every READY document in the bundle and insert any new
     * rows into the inventory. Returns a compact result object the
     * controller can show in a toast.
     */
    @Transactional
    public ExtractionResult extractForBundle(String bundleId) {
        long t0 = System.currentTimeMillis();
        List<ResearchDocument> docs = documentRepo.findByBundleIdOrderByUploadedAtDesc(bundleId)
                .stream().filter(d -> d.getStatus() == IngestStatus.READY).toList();

        if (docs.isEmpty()) {
            return ExtractionResult.empty();
        }

        // Build an existing-items index once so duplicate detection is
        // O(1) instead of hitting the DB per candidate.
        Set<String> existingKeys = new HashSet<>();
        for (InventoryItem it : inventoryRepo.findByBundleIdOrderByUpdatedAtDesc(bundleId)) {
            existingKeys.add(dedupeKey(it.getKind(), it.getName()));
        }

        // We also dedupe within this run so the same port showing up in
        // twenty chunks only ends up as a single new row.
        Map<String, InventoryItem> pending = new LinkedHashMap<>();

        int chunksScanned = 0;
        for (ResearchDocument doc : docs) {
            List<ResearchDocumentChunk> chunks =
                    chunkRepo.findByDocumentIdOrderByOrdinalAsc(doc.getId());
            for (ResearchDocumentChunk c : chunks) {
                chunksScanned++;
                String text = c.getText() == null ? "" : c.getText();
                String sourceRef = "doc:" + doc.getId() + "#chunk:" + c.getOrdinal();
                scanChunk(bundleId, sourceRef, text, existingKeys, pending);
            }
        }

        LocalDateTime now = LocalDateTime.now();
        for (InventoryItem it : pending.values()) {
            it.setCreatedAt(now);
            it.setUpdatedAt(now);
            inventoryRepo.save(it);
        }

        Map<Kind, Integer> createdByKind = new EnumMap<>(Kind.class);
        for (InventoryItem it : pending.values()) {
            createdByKind.merge(it.getKind(), 1, Integer::sum);
        }

        log.info("Extract: bundle={} scanned {} chunks across {} docs, created {} new items in {} ms",
                bundleId, chunksScanned, docs.size(), pending.size(),
                System.currentTimeMillis() - t0);

        return new ExtractionResult(
                docs.size(),
                chunksScanned,
                pending.size(),
                createdByKind.getOrDefault(Kind.PORT, 0),
                createdByKind.getOrDefault(Kind.PROTOCOL, 0),
                createdByKind.getOrDefault(Kind.SERVICE, 0)
        );
    }

    // ---- Core regex scan for one chunk --------------------------------

    private void scanChunk(String bundleId,
                           String sourceRef,
                           String text,
                           Set<String> existingKeys,
                           Map<String, InventoryItem> pending) {

        // --- Ports: "502/tcp", "port 4840/udp"
        Matcher m1 = PORT_PATTERN.matcher(text);
        while (m1.find()) {
            String port = m1.group(1);
            String proto = m1.group(2).toUpperCase();
            String name = "Port " + port + "/" + proto;
            maybeAdd(bundleId, sourceRef, Kind.PORT, name, null, existingKeys, pending);
        }

        // --- Ports: "TCP port 502"
        Matcher m2 = PORT_WORD_PATTERN.matcher(text);
        while (m2.find()) {
            String proto = m2.group(1).toUpperCase();
            String port = m2.group(2);
            String name = "Port " + port + "/" + proto;
            maybeAdd(bundleId, sourceRef, Kind.PORT, name, null, existingKeys, pending);
        }

        // --- Protocols
        for (NamedPattern p : PROTOCOL_PATTERNS) {
            if (p.pattern.matcher(text).find()) {
                maybeAdd(bundleId, sourceRef, Kind.PROTOCOL, p.label, null, existingKeys, pending);
            }
        }

        // --- Services
        for (NamedPattern p : SERVICE_PATTERNS) {
            if (p.pattern.matcher(text).find()) {
                maybeAdd(bundleId, sourceRef, Kind.SERVICE, p.label, null, existingKeys, pending);
            }
        }
    }

    /**
     * Record a candidate row unless an identical one already exists in
     * the bundle or the same run. Preserves first-seen source ref so
     * the researcher lands on the earliest passage that mentions it.
     */
    private void maybeAdd(String bundleId,
                          String sourceRef,
                          Kind kind,
                          String name,
                          String reference,
                          Set<String> existingKeys,
                          Map<String, InventoryItem> pending) {
        String key = dedupeKey(kind, name);
        if (existingKeys.contains(key) || pending.containsKey(key)) {
            return;
        }
        InventoryItem item = InventoryItem.builder()
                .id(UUID.randomUUID().toString())
                .bundleId(bundleId)
                .kind(kind)
                .name(name)
                .reference(reference)
                .source(sourceRef)
                .tags("auto,regex")
                .build();
        pending.put(key, item);
    }

    private static String dedupeKey(Kind kind, String name) {
        String n = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
        return kind.name() + "||" + n;
    }

    // ---- Helpers ------------------------------------------------------

    private record NamedPattern(String label, Pattern pattern) {}

    private static NamedPattern np(String label, String regex) {
        return new NamedPattern(label, Pattern.compile(regex));
    }

    /**
     * Summary of one extraction pass. Returned to the controller,
     * rendered in the UI as a toast.
     */
    public record ExtractionResult(
            int documentsScanned,
            int chunksScanned,
            int itemsCreated,
            int portsCreated,
            int protocolsCreated,
            int servicesCreated
    ) {
        public static ExtractionResult empty() {
            return new ExtractionResult(0, 0, 0, 0, 0, 0);
        }
    }
}

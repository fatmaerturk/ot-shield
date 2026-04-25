package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.model.research.ResearchDocument.IngestStatus;
import com.safetech.otshield.model.research.ResearchDocumentChunk;
import com.safetech.otshield.model.research.VulnEvent;
import com.safetech.otshield.model.research.VulnObservation;
import com.safetech.otshield.model.research.VulnObservation.ComponentType;
import com.safetech.otshield.model.research.VulnObservation.VulnConfidence;
import com.safetech.otshield.model.research.VulnObservation.VulnSeverity;
import com.safetech.otshield.model.research.VulnObservation.VulnStatus;
import com.safetech.otshield.repository.research.ResearchDocumentChunkRepository;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import com.safetech.otshield.repository.research.VulnEventRepository;
import com.safetech.otshield.repository.research.VulnObservationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, regex-based "first-pass" security triage over a
 * bundle's documents. Produces draft {@link VulnObservation} rows
 * that the researcher can then verify, edit, or dismiss - never a
 * confirmed finding on its own.
 *
 * <p>HMGCC brief alignment:
 *
 * <ul>
 *   <li><b>"Check and validate responses before publishing":</b> every
 *       signal lands as {@link VulnStatus#DRAFT} with
 *       {@code needsMoreSources=true} and {@code confidence=LOW}.
 *       Nothing here is treated as ground truth.</li>
 *   <li><b>"Flag a confidence score":</b> the regex layer cannot
 *       establish causality, so all of its output is LOW confidence
 *       by construction; the researcher elevates it to MEDIUM/HIGH
 *       manually once they have verified the passage in context.</li>
 *   <li><b>Offline-first:</b> no model inference, no external feeds.
 *       Millisecond-latency pass over chunks already in the DB.</li>
 * </ul>
 *
 * <p>Design notes:
 *
 * <ul>
 *   <li>Dedupe is by {@code (bundleId, lowercase title)} so re-running
 *       the scan doesn't pile up duplicate drafts.</li>
 *   <li>Each produced observation carries a bounded-length excerpt
 *       from the first chunk that matched, plus the doc name / page
 *       number in {@code componentRef} so the analyst can jump back.</li>
 *   <li>A corresponding {@link VulnEvent} is written so the audit
 *       trail reflects the scanner as the origin.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VulnSignalScanner {

    private final ResearchDocumentRepository documentRepo;
    private final ResearchDocumentChunkRepository chunkRepo;
    private final VulnObservationRepository vulnRepo;
    private final VulnEventRepository eventRepo;

    /** Max excerpt length stored in the observation's summary. */
    private static final int EXCERPT_LIMIT = 400;

    /**
     * Rule definition: a regex plus the draft observation fields to
     * produce when it fires. {@code category} groups rules for the
     * scan-result breakdown the UI surfaces.
     */
    private record Rule(
            String category,
            String title,
            Pattern pattern,
            ComponentType componentType,
            VulnSeverity severity
    ) {}

    /**
     * Rule library. Small and conservative - we add patterns as we
     * see false-positive-free evidence from real manuals. Every rule
     * matches vendor-manual / datasheet wording rather than source
     * code, because that's what our corpus is.
     */
    private static final List<Rule> RULES = List.of(
            // --- Insecure remote / management protocols --------------
            rule("insecure-remote", "Telnet management surface mentioned",
                    "(?i)\\btelnet\\b.*\\b(?:enabled|listening|default|admin|management)\\b|" +
                    "\\b(?:enable|default)\\b.*\\btelnet\\b",
                    ComponentType.PROTOCOL, VulnSeverity.HIGH),
            // "FTP/TFTP/RSH/VNC/RDP" etc. are remote-access interfaces in
            // HMGCC terminology ("physical interface interactions, data
            // interfaces and protocols"); the vuln enum has no SERVICE
            // kind, so we bucket them under INTERFACE which is the
            // nearest match.
            rule("insecure-remote", "FTP service mentioned",
                    "(?i)\\bftp\\b.*\\b(?:enabled|listening|anonymous|default)\\b|" +
                    "\\banonymous\\s+ftp\\b",
                    ComponentType.INTERFACE, VulnSeverity.MEDIUM),
            rule("insecure-remote", "TFTP service mentioned",
                    "(?i)\\btftp\\b",
                    ComponentType.INTERFACE, VulnSeverity.MEDIUM),
            rule("insecure-remote", "RSH/RLOGIN service mentioned",
                    "(?i)\\br(?:sh|login|exec|cp)\\b",
                    ComponentType.INTERFACE, VulnSeverity.HIGH),
            rule("insecure-remote", "VNC mentioned",
                    "(?i)\\bvnc\\b",
                    ComponentType.INTERFACE, VulnSeverity.MEDIUM),
            rule("insecure-remote", "RDP mentioned",
                    "(?i)\\brdp\\b|\\bremote\\s+desktop\\s+protocol\\b",
                    ComponentType.INTERFACE, VulnSeverity.MEDIUM),

            // --- Weak or hardcoded authentication --------------------
            rule("weak-auth", "Default credentials mentioned",
                    "(?i)\\bdefault\\s+(?:user(?:name)?|password|credential|login)s?\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.HIGH),
            rule("weak-auth", "Hardcoded credentials mentioned",
                    "(?i)\\bhard[-\\s]?coded\\s+(?:password|credential|key|secret)s?\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.HIGH),
            rule("weak-auth", "Factory/admin/admin style default",
                    "(?i)\\b(admin|root|user)\\s*[:=/]\\s*(admin|root|password|1234|0000|changeme)\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.HIGH),
            rule("weak-auth", "Password stored in plaintext",
                    "(?i)\\bpassword\\b.*\\b(?:plain[-\\s]?text|clear[-\\s]?text|unencrypted)\\b|" +
                    "\\b(?:plain[-\\s]?text|clear[-\\s]?text)\\s+password\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.HIGH),
            rule("weak-auth", "No authentication mentioned",
                    "(?i)\\bno\\s+authentication\\b|\\bauthentication\\s+(?:is\\s+)?(?:not\\s+required|disabled)\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.HIGH),

            // --- Weak cryptography -----------------------------------
            rule("crypto", "MD5 in use",
                    "(?i)\\bmd5\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.MEDIUM),
            rule("crypto", "SHA-1 in use",
                    "(?i)\\bsha[-\\s]?1\\b",
                    ComponentType.CONFIGURATION, VulnSeverity.LOW),
            rule("crypto", "Unencrypted / plaintext traffic",
                    "(?i)\\b(?:unencrypted|cleartext|plaintext)\\s+(?:traffic|communication|channel|data)\\b",
                    ComponentType.PROTOCOL, VulnSeverity.MEDIUM),
            rule("crypto", "TLS 1.0 / 1.1 (legacy)",
                    "(?i)\\btls\\s*1\\.[01]\\b|\\bssl\\s*v?[23]\\b",
                    ComponentType.PROTOCOL, VulnSeverity.MEDIUM),

            // --- Firmware integrity ----------------------------------
            rule("firmware", "Unsigned firmware",
                    "(?i)\\bunsigned\\s+firmware\\b|" +
                    "\\bfirmware\\b.*\\bnot\\s+signed\\b|" +
                    "\\bno\\s+(?:firmware\\s+)?signature\\s+check\\b",
                    ComponentType.FIRMWARE, VulnSeverity.HIGH),
            rule("firmware", "No integrity check mentioned",
                    "(?i)\\bno\\s+integrity\\s+check\\b|" +
                    "\\bintegrity\\s+check\\s+(?:is\\s+)?(?:disabled|not\\s+performed)\\b",
                    ComponentType.FIRMWARE, VulnSeverity.MEDIUM),
            rule("firmware", "Firmware update over insecure channel",
                    "(?i)\\bfirmware\\s+update\\b.*\\b(?:http|ftp|tftp)\\b(?!s)",
                    ComponentType.FIRMWARE, VulnSeverity.HIGH),

            // --- Known-CVE mentions ----------------------------------
            rule("cve", "CVE identifier mentioned",
                    "\\bCVE-\\d{4}-\\d{4,7}\\b",
                    ComponentType.SOFTWARE, VulnSeverity.MEDIUM)
    );

    private static Rule rule(String cat, String title, String regex,
                             ComponentType ct, VulnSeverity sev) {
        return new Rule(cat, title, Pattern.compile(regex), ct, sev);
    }

    // ---- Public entry point -------------------------------------------

    /**
     * Run every rule against every READY chunk in the bundle, writing
     * any new drafts to {@link VulnObservation}. Returns counts for
     * the UI toast.
     */
    @Transactional
    public SignalScanResult scanForBundle(String bundleId) {
        long t0 = System.currentTimeMillis();
        List<ResearchDocument> docs = documentRepo.findByBundleIdOrderByUploadedAtDesc(bundleId)
                .stream().filter(d -> d.getStatus() == IngestStatus.READY).toList();

        if (docs.isEmpty()) {
            return SignalScanResult.empty();
        }

        // Existing drafts we don't want to re-create. Dedupe key is
        // (bundleId, lowercase title) because scanner output always
        // uses the rule title verbatim.
        Set<String> existingKeys = new HashSet<>();
        for (VulnObservation v : vulnRepo.findByBundleIdOrderByUpdatedAtDesc(bundleId)) {
            existingKeys.add(dedupeKey(v.getTitle()));
        }

        // Run each rule, record the first chunk each rule matches so
        // the draft has a concrete excerpt and source ref.
        Map<String, Hit> hitsByTitle = new LinkedHashMap<>();
        int chunksScanned = 0;
        for (ResearchDocument doc : docs) {
            List<ResearchDocumentChunk> chunks =
                    chunkRepo.findByDocumentIdOrderByOrdinalAsc(doc.getId());
            for (ResearchDocumentChunk c : chunks) {
                chunksScanned++;
                String text = c.getText() == null ? "" : c.getText();
                if (text.isEmpty()) continue;
                for (Rule r : RULES) {
                    if (hitsByTitle.containsKey(r.title())) continue; // first hit wins per rule
                    Matcher m = r.pattern().matcher(text);
                    if (m.find()) {
                        hitsByTitle.put(r.title(), new Hit(r, doc, c, extractWindow(text, m)));
                    }
                }
            }
        }

        // Persist new drafts and count per-category creations.
        Map<String, Integer> createdByCategory = new LinkedHashMap<>();
        int created = 0;
        LocalDateTime now = LocalDateTime.now();
        for (Hit hit : hitsByTitle.values()) {
            if (existingKeys.contains(dedupeKey(hit.rule.title()))) continue;

            String componentRef = hit.doc.getFileName()
                    + (hit.chunk.getPageNumber() == null ? "" : " · p." + hit.chunk.getPageNumber());

            VulnObservation draft = VulnObservation.builder()
                    .title(hit.rule.title())
                    .summary(hit.excerpt)
                    .componentType(hit.rule.componentType())
                    .componentRef(componentRef)
                    .severity(hit.rule.severity())
                    .confidence(VulnConfidence.LOW)
                    .needsMoreSources(true)
                    .status(VulnStatus.DRAFT)
                    .bundleId(bundleId)
                    .tags("auto,signal," + hit.rule.category())
                    .createdAt(now)
                    .updatedAt(now)
                    .createdBy("vuln-signal-scanner")
                    .build();
            VulnObservation saved = vulnRepo.save(draft);

            eventRepo.save(VulnEvent.builder()
                    .vulnId(saved.getId())
                    .kind(VulnEvent.EventKind.CREATED)
                    .comment("Auto-drafted by regex signal scanner from "
                            + hit.doc.getFileName()
                            + (hit.chunk.getPageNumber() == null ? "" : " (page " + hit.chunk.getPageNumber() + ")"))
                    .actor("vuln-signal-scanner")
                    .createdAt(now)
                    .build());

            created++;
            createdByCategory.merge(hit.rule.category(), 1, Integer::sum);
        }

        log.info("VulnSignals: bundle={} scanned {} chunks across {} docs, wrote {} drafts in {} ms",
                bundleId, chunksScanned, docs.size(), created, System.currentTimeMillis() - t0);

        return new SignalScanResult(
                docs.size(),
                chunksScanned,
                created,
                createdByCategory.getOrDefault("insecure-remote", 0),
                createdByCategory.getOrDefault("weak-auth", 0),
                createdByCategory.getOrDefault("crypto", 0),
                createdByCategory.getOrDefault("firmware", 0),
                createdByCategory.getOrDefault("cve", 0)
        );
    }

    // ---- Helpers ------------------------------------------------------

    private record Hit(Rule rule, ResearchDocument doc, ResearchDocumentChunk chunk, String excerpt) {}

    /**
     * Pull a tight window around the match so the saved excerpt is
     * something a researcher can skim-read (~20 words either side).
     * Collapses whitespace to keep the UI legible.
     */
    private static String extractWindow(String text, Matcher m) {
        int start = Math.max(0, m.start() - 140);
        int end = Math.min(text.length(), m.end() + 140);
        String window = text.substring(start, end).replaceAll("\\s+", " ").trim();
        if (start > 0) window = "..." + window;
        if (end < text.length()) window = window + "...";
        return window.length() <= EXCERPT_LIMIT
                ? window
                : window.substring(0, EXCERPT_LIMIT - 3) + "...";
    }

    private static String dedupeKey(String title) {
        return title == null ? "" : title.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Return shape for the scan endpoint. Per-category counts power
     * the UI toast; total and corpus size let the analyst see that
     * the scan actually ran against something.
     */
    public record SignalScanResult(
            int documentsScanned,
            int chunksScanned,
            int draftsCreated,
            int insecureRemoteCount,
            int weakAuthCount,
            int cryptoCount,
            int firmwareCount,
            int cveCount
    ) {
        public static SignalScanResult empty() {
            return new SignalScanResult(0, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}

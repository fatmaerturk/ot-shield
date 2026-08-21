package com.safetech.otshield.service;

import com.safetech.otshield.dto.cases.CaseArtifactRequest;
import com.safetech.otshield.dto.cases.CaseDTO;
import com.safetech.otshield.dto.cases.CreateCaseRequest;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.*;
import com.safetech.otshield.repository.CaseRepository;
import com.safetech.otshield.repository.HoneypotLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Generates SOC cases from REAL decoy telemetry instead of demo seed data.
 *
 * It aggregates captured honeypot events by attacker IP and opens a case for the
 * most aggressive real sources - the ones sustaining reconnaissance or credential
 * attacks against the deception fabric. Every field (IP, country, protocols,
 * technique classes, interaction count, first/last seen, credential attempts) is
 * first-party evidence, and the IP is attached as a real IOC.
 *
 * Idempotent: each attacker IP is cased at most once (deduped by a "src:&lt;ip&gt;"
 * tag), and the total number of auto-generated cases is capped so the queue never
 * floods. Runs at startup and periodically.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RealCaseGeneratorService {

    private final HoneypotLogRepository honeypotRepo;
    private final CaseService caseService;
    private final CaseRepository caseRepository;

    private static final int MIN_EVENTS = 25;       // warrant a case only for real, sustained activity
    private static final int MAX_TOTAL_AUTO = 8;     // cap the auto-generated backlog
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private static class Agg {
        final String ip;
        int count;
        int credAttempts;
        String country;
        final Set<String> protocols = new LinkedHashSet<>();
        final Set<String> attackTypes = new LinkedHashSet<>();
        LocalDateTime first;
        LocalDateTime last;
        Agg(String ip) { this.ip = ip; }
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        generate();
    }

    @Scheduled(fixedDelay = 300000, initialDelay = 45000)
    public void scheduled() {
        generate();
    }

    @Transactional
    public void generate() {
        // Which attacker IPs already have a case, and how many auto-cases exist.
        Set<String> alreadyCased = new HashSet<>();
        int autoCount = 0;
        try {
            for (Case c : caseRepository.findAll()) {
                Set<String> tags = c.getTags();
                if (tags == null) continue;
                if (tags.contains("auto")) autoCount++;
                for (String t : tags) if (t.startsWith("src:")) alreadyCased.add(t.substring(4));
            }
        } catch (Exception e) {
            return;
        }
        int budget = MAX_TOTAL_AUTO - autoCount;
        if (budget <= 0) return;

        // Aggregate real telemetry by source IP.
        List<HoneypotLog> logs;
        try {
            logs = honeypotRepo.findTop8000ByOrderByTimestampDesc();
        } catch (Exception e) {
            return;
        }
        Map<String, Agg> byIp = new HashMap<>();
        for (HoneypotLog l : logs) {
            if (HoneypotLogService.isInternalNoise(l)) continue;
            String ip = l.getSourceIp();
            if (ip == null || ip.isBlank()) continue;
            Agg a = byIp.computeIfAbsent(ip, Agg::new);
            a.count++;
            if (l.getProtocol() != null && !l.getProtocol().isBlank()) a.protocols.add(l.getProtocol());
            if (l.getAttackType() != null && !l.getAttackType().isBlank()) a.attackTypes.add(l.getAttackType());
            if (a.country == null && l.getCountry() != null && !l.getCountry().isBlank()) a.country = l.getCountry();
            if (l.getUsernameAttempt() != null && !l.getUsernameAttempt().isBlank()) a.credAttempts++;
            LocalDateTime ts = l.getTimestamp();
            if (ts != null) {
                if (a.first == null || ts.isBefore(a.first)) a.first = ts;
                if (a.last == null || ts.isAfter(a.last)) a.last = ts;
            }
        }

        // Rank the most aggressive, not-yet-cased sources; open cases within budget.
        List<Agg> candidates = new ArrayList<>();
        for (Agg a : byIp.values()) {
            if (a.count >= MIN_EVENTS && !alreadyCased.contains(a.ip)) candidates.add(a);
        }
        candidates.sort((x, y) -> Integer.compare(y.count, x.count));

        int created = 0;
        for (Agg a : candidates) {
            if (created >= budget) break;
            try {
                openCase(a);
                created++;
            } catch (Exception e) {
                log.warn("RealCaseGenerator: failed to open case for {}: {}", a.ip, e.getMessage());
            }
        }
        if (created > 0) log.info("RealCaseGenerator: opened {} case(s) from real telemetry", created);
    }

    private void openCase(Agg a) {
        boolean creds = a.credAttempts > 0;
        String country = a.country == null ? "unknown origin" : a.country;
        String protoList = a.protocols.isEmpty() ? "ICS" : String.join(", ", a.protocols);
        String techList = a.attackTypes.isEmpty() ? "reconnaissance" : String.join(", ", a.attackTypes);
        String span = (a.first != null && a.last != null)
            ? a.first.format(TS) + " to " + a.last.format(TS) : "recent activity";

        String title = creds
            ? "Credential attack from " + a.ip + " (" + country + ")"
            : "Sustained ICS probing from " + a.ip + " (" + country + ")";

        String description = a.ip + " engaged the OT decoy fabric with " + a.count + " interactions ("
            + span + ").\n\n"
            + "Protocols probed: " + protoList + "\n"
            + "Technique classes: " + techList + "\n"
            + (creds ? "Credential attempts captured: " + a.credAttempts + "\n" : "")
            + "\nAll figures are first-party evidence from the deception fabric. The source IP is "
            + "attached as an IOC below.";

        CasePriority priority = creds || a.count >= 200 ? CasePriority.HIGH : CasePriority.MEDIUM;
        AlertSeverity severity = creds || a.count >= 200 ? AlertSeverity.HIGH : AlertSeverity.MEDIUM;
        CaseCategory category = creds ? CaseCategory.UNAUTHORIZED_ACCESS : CaseCategory.RECON;

        Set<String> tags = new LinkedHashSet<>();
        tags.add("decoy");
        tags.add("auto");
        tags.add("real-telemetry");
        tags.add("src:" + a.ip);
        if (a.country != null) tags.add("country:" + a.country.toLowerCase());
        for (String p : a.protocols) tags.add("proto:" + p.toLowerCase());

        CreateCaseRequest req = CreateCaseRequest.builder()
            .title(title)
            .description(description)
            .priority(priority)
            .severity(severity)
            .category(category)
            .reporterName("OTShield Correlation")
            .tags(tags)
            .build();

        CaseDTO created = caseService.create(req);

        // Real IOCs: the attacker IP, plus each probed protocol.
        caseService.addArtifact(created.getId(), CaseArtifactRequest.builder()
            .artifactType(CaseArtifactType.IP)
            .value(a.ip)
            .label("Attacker source IP")
            .description(country + (a.attackTypes.isEmpty() ? "" : " - " + techList(a)))
            .malicious(true)
            .actorName("OTShield Correlation")
            .build());
    }

    private static String techList(Agg a) {
        return a.attackTypes.isEmpty() ? "reconnaissance" : String.join(", ", a.attackTypes);
    }
}

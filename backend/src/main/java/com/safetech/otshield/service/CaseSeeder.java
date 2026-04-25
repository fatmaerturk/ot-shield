package com.safetech.otshield.service;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.*;
import com.safetech.otshield.repository.CaseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Seeds demo cases on first boot so the SOC analyst UI has something to look at.
 * Safe to run repeatedly: exits early if any cases exist.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CaseSeeder {

    private final CaseRepository caseRepository;

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void seed() {
        if (caseRepository.count() > 0) {
            log.info("CaseSeeder: cases already exist (count={}), skipping", caseRepository.count());
            return;
        }
        LocalDateTime now = LocalDateTime.now();

        // Case 1 - active investigation
        Case c1 = Case.builder()
                .caseNumber("CASE-2026-0001")
                .title("Suspicious MODBUS writes from 203.0.113.42")
                .description("Repeated MODBUS function 0x06 (write single register) attempts targeting water treatment PLCs at L2 zone. Source IP geolocates to hosting provider in RU.")
                .status(CaseStatus.INVESTIGATING)
                .priority(CasePriority.HIGH)
                .severity(AlertSeverity.HIGH)
                .category(CaseCategory.UNAUTHORIZED_ACCESS)
                .assigneeId("analyst-1")
                .assigneeName("F. Ertürk")
                .reporterName("auto-correlate")
                .createdAt(now.minusHours(4).minusMinutes(13))
                .acknowledgedAt(now.minusHours(4).minusMinutes(5))
                .mttAcknowledgeSeconds(8L * 60)
                .tags(new HashSet<>(Arrays.asList("modbus", "l2", "water-treatment", "active")))
                .artifacts(new ArrayList<>())
                .timeline(new ArrayList<>())
                .linkedAlerts(new HashSet<>())
                .build();
        c1.getTimeline().add(timeline(c1, CaseTimelineEntryType.CREATED, "auto-correlate",
                "Case auto-created from 3 correlated alerts", now.minusHours(4).minusMinutes(13)));
        c1.getTimeline().add(timeline(c1, CaseTimelineEntryType.ASSIGNED, "soc-lead",
                "Assigned to F. Ertürk", now.minusHours(4).minusMinutes(10)));
        c1.getTimeline().add(timeline(c1, CaseTimelineEntryType.STATUS_CHANGE, "F. Ertürk",
                "Status NEW → TRIAGING", now.minusHours(4).minusMinutes(5)));
        c1.getTimeline().add(timeline(c1, CaseTimelineEntryType.COMMENT, "F. Ertürk",
                "Peer-reviewed PCAP - looks like a scripted probe. Checking if any writes succeeded.",
                now.minusHours(3).minusMinutes(40)));
        c1.getTimeline().add(timeline(c1, CaseTimelineEntryType.STATUS_CHANGE, "F. Ertürk",
                "Status TRIAGING → INVESTIGATING", now.minusHours(3).minusMinutes(20)));
        c1.getTimeline().add(timeline(c1, CaseTimelineEntryType.ARTIFACT_ADDED, "F. Ertürk",
                "IP: 203.0.113.42", now.minusHours(3).minusMinutes(10)));
        c1.getArtifacts().add(artifact(c1, CaseArtifactType.IP, "203.0.113.42",
                "Attacker source IP", "Geo: RU · ASN: AS49505", "F. Ertürk",
                now.minusHours(3).minusMinutes(10), true));
        c1.getArtifacts().add(artifact(c1, CaseArtifactType.IP, "10.4.12.21",
                "Target PLC", "Siemens S7-1500 · Purdue L2", "F. Ertürk",
                now.minusHours(3).minusMinutes(9), false));
        c1.getArtifacts().add(artifact(c1, CaseArtifactType.OTHER, "MODBUS fn=0x06",
                "Write Single Register", "Attempted holding register write", "F. Ertürk",
                now.minusHours(3).minusMinutes(8), true));

        // Case 2 - resolved yesterday
        Case c2 = Case.builder()
                .caseNumber("CASE-2026-0002")
                .title("Failed SSH brute force on engineering workstation")
                .description("42 failed password attempts against eng-ws-07 over 6 minutes. Account lockout triggered. No success.")
                .status(CaseStatus.RESOLVED)
                .priority(CasePriority.MEDIUM)
                .severity(AlertSeverity.MEDIUM)
                .category(CaseCategory.RECON)
                .assigneeId("analyst-2")
                .assigneeName("M. Demir")
                .reporterName("auto-correlate")
                .createdAt(now.minusDays(1).minusHours(2))
                .acknowledgedAt(now.minusDays(1).minusHours(2).plusMinutes(3))
                .resolvedAt(now.minusDays(1).minusHours(1))
                .mttAcknowledgeSeconds(3L * 60)
                .mttResolveSeconds(60L * 60)
                .resolutionSummary("Attacker IP blocked at perimeter. No credentials compromised. Lockout policy working as designed.")
                .tags(new HashSet<>(Arrays.asList("ssh", "brute-force", "blocked")))
                .artifacts(new ArrayList<>())
                .timeline(new ArrayList<>())
                .linkedAlerts(new HashSet<>())
                .build();
        c2.getTimeline().add(timeline(c2, CaseTimelineEntryType.CREATED, "auto-correlate",
                "Case auto-created from brute-force detection", now.minusDays(1).minusHours(2)));
        c2.getTimeline().add(timeline(c2, CaseTimelineEntryType.ASSIGNED, "soc-lead",
                "Assigned to M. Demir", now.minusDays(1).minusHours(2).plusMinutes(1)));
        c2.getTimeline().add(timeline(c2, CaseTimelineEntryType.COMMENT, "M. Demir",
                "Confirmed lockout fired. No creds leaked.", now.minusDays(1).minusHours(1).minusMinutes(30)));
        c2.getTimeline().add(timeline(c2, CaseTimelineEntryType.STATUS_CHANGE, "M. Demir",
                "Status INVESTIGATING → RESOLVED", now.minusDays(1).minusHours(1)));
        c2.getTimeline().add(timeline(c2, CaseTimelineEntryType.RESOLUTION, "M. Demir",
                c2.getResolutionSummary(), now.minusDays(1).minusHours(1)));
        c2.getArtifacts().add(artifact(c2, CaseArtifactType.IP, "198.51.100.17",
                "Attacker IP", "Blocked at edge firewall", "M. Demir",
                now.minusDays(1).minusHours(1), true));

        // Case 3 - new, unassigned
        Case c3 = Case.builder()
                .caseNumber("CASE-2026-0003")
                .title("Unknown asset appeared on L2 segment (10.4.12.99)")
                .description("Anomaly detector flagged a previously-unseen MAC address communicating MODBUS TCP to 4 PLCs. No matching asset in inventory.")
                .status(CaseStatus.NEW)
                .priority(CasePriority.CRITICAL)
                .severity(AlertSeverity.CRITICAL)
                .category(CaseCategory.ANOMALY)
                .reporterName("baseline-detector")
                .createdAt(now.minusMinutes(18))
                .tags(new HashSet<>(Arrays.asList("new-device", "l2", "rogue")))
                .artifacts(new ArrayList<>())
                .timeline(new ArrayList<>())
                .linkedAlerts(new HashSet<>())
                .build();
        c3.getTimeline().add(timeline(c3, CaseTimelineEntryType.CREATED, "baseline-detector",
                "New asset detected on trusted segment", now.minusMinutes(18)));
        c3.getArtifacts().add(artifact(c3, CaseArtifactType.IP, "10.4.12.99",
                "Rogue asset", "Unknown MAC b4:2e:99:..", "baseline-detector",
                now.minusMinutes(18), true));

        // Case 4 - false positive closed
        Case c4 = Case.builder()
                .caseNumber("CASE-2026-0004")
                .title("After-hours login - Jenkins scheduled job")
                .description("Login from jenkins-svc@eng-ws-02 at 03:14. Triggered off-hours anomaly rule.")
                .status(CaseStatus.FALSE_POSITIVE)
                .priority(CasePriority.LOW)
                .severity(AlertSeverity.LOW)
                .category(CaseCategory.POLICY_VIOLATION)
                .assigneeId("analyst-1")
                .assigneeName("F. Ertürk")
                .reporterName("auto-correlate")
                .createdAt(now.minusDays(2))
                .acknowledgedAt(now.minusDays(2).plusMinutes(8))
                .resolvedAt(now.minusDays(2).plusMinutes(22))
                .mttAcknowledgeSeconds(8L * 60)
                .mttResolveSeconds(22L * 60)
                .resolutionSummary("Scheduled build job running as service account. Added service account to off-hours allowlist.")
                .tags(new HashSet<>(Arrays.asList("false-positive", "service-account")))
                .artifacts(new ArrayList<>())
                .timeline(new ArrayList<>())
                .linkedAlerts(new HashSet<>())
                .build();
        c4.getTimeline().add(timeline(c4, CaseTimelineEntryType.CREATED, "auto-correlate",
                "Off-hours login anomaly", now.minusDays(2)));
        c4.getTimeline().add(timeline(c4, CaseTimelineEntryType.STATUS_CHANGE, "F. Ertürk",
                "Status NEW → FALSE_POSITIVE", now.minusDays(2).plusMinutes(22)));
        c4.getTimeline().add(timeline(c4, CaseTimelineEntryType.RESOLUTION, "F. Ertürk",
                c4.getResolutionSummary(), now.minusDays(2).plusMinutes(22)));

        // Case 5 - contained, awaiting resolution
        Case c5 = Case.builder()
                .caseNumber("CASE-2026-0005")
                .title("HMI exposed to internet - Shodan scan hit")
                .description("External threat intel feed reported our substation HMI at public IP 185.22.11.74 visible on Shodan. Access logs show scans from 7 distinct IPs.")
                .status(CaseStatus.CONTAINED)
                .priority(CasePriority.HIGH)
                .severity(AlertSeverity.HIGH)
                .category(CaseCategory.UNAUTHORIZED_ACCESS)
                .assigneeId("analyst-2")
                .assigneeName("M. Demir")
                .reporterName("threat-intel-feed")
                .createdAt(now.minusHours(19))
                .acknowledgedAt(now.minusHours(19).plusMinutes(4))
                .containedAt(now.minusHours(16))
                .mttAcknowledgeSeconds(4L * 60)
                .mttContainSeconds(3L * 60 * 60)
                .tags(new HashSet<>(Arrays.asList("exposure", "substation", "shodan")))
                .artifacts(new ArrayList<>())
                .timeline(new ArrayList<>())
                .linkedAlerts(new HashSet<>())
                .build();
        c5.getTimeline().add(timeline(c5, CaseTimelineEntryType.CREATED, "threat-intel-feed",
                "Shodan exposure alert", now.minusHours(19)));
        c5.getTimeline().add(timeline(c5, CaseTimelineEntryType.STATUS_CHANGE, "M. Demir",
                "Status NEW → CONTAINED - firewall rule pushed blocking 185.22.11.74:502 from internet",
                now.minusHours(16)));
        c5.getArtifacts().add(artifact(c5, CaseArtifactType.IP, "185.22.11.74",
                "Exposed HMI IP", "Substation HMI · Siemens WinCC", "M. Demir",
                now.minusHours(18), false));
        c5.getArtifacts().add(artifact(c5, CaseArtifactType.DOMAIN, "shodan.io",
                "Source of disclosure", "Public scanner", "threat-intel-feed",
                now.minusHours(19), false));

        caseRepository.saveAll(List.of(c1, c2, c3, c4, c5));
        log.info("CaseSeeder: seeded {} demo cases", caseRepository.count());
    }

    private static CaseTimelineEntry timeline(Case c, CaseTimelineEntryType type, String actor,
                                              String content, LocalDateTime ts) {
        return CaseTimelineEntry.builder()
                .caseEntity(c)
                .entryType(type)
                .actorName(actor)
                .content(content)
                .ts(ts)
                .build();
    }

    private static CaseArtifact artifact(Case c, CaseArtifactType type, String value,
                                         String label, String desc, String addedBy,
                                         LocalDateTime addedAt, boolean malicious) {
        return CaseArtifact.builder()
                .caseEntity(c)
                .artifactType(type)
                .value(value)
                .label(label)
                .description(desc)
                .addedBy(addedBy)
                .addedAt(addedAt)
                .malicious(malicious)
                .build();
    }

    // kept to illustrate that ChronoUnit is a valid import path for compile-time use elsewhere
    @SuppressWarnings("unused")
    private static long secondsBetween(LocalDateTime from, LocalDateTime to) {
        return ChronoUnit.SECONDS.between(from, to);
    }
}

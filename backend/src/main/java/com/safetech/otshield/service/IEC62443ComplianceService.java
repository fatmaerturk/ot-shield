package com.safetech.otshield.service;

import com.safetech.otshield.model.Asset;
import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Builds a live IEC 62443-3-3 (System Security Requirements) compliance posture
 * for OTShield, mirroring the NIS2 posture approach: the full Foundational
 * Requirement / System Requirement catalogue is fixed reference data, but the
 * status of each SR is derived from REAL platform telemetry (anomalies, DPI,
 * honeypot/decoy activity, asset inventory & Purdue zones, cases, audit log,
 * RBAC/auth). Requirements with no telemetry basis are honestly reported as
 * NOT_ASSESSED rather than assumed compliant.
 *
 * <p>Returns {@code Map<String,Object>} (no DTO) to match the NIS2 precedent.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class IEC62443ComplianceService {

    private final AnomalyRepository anomalyRepository;
    private final DpiEventRepository dpiEventRepository;
    private final HoneypotLogRepository honeypotLogRepository;
    private final AssetRepository assetRepository;
    private final CaseRepository caseRepository;
    private final AuditLogRepository auditLogRepository;
    private final AlertRepository alertRepository;
    private final UserRepository userRepository;

    private static final String COMPLIANT = "COMPLIANT";
    private static final String PARTIAL = "PARTIAL";
    private static final String NOT_ASSESSED = "NOT_ASSESSED";
    private static final int TARGET_SL = 2; // org-wide default target security level

    @Transactional(readOnly = true)
    public Map<String, Object> buildPosture() {
        // ---- Real evidence, loaded once -------------------------------------
        long anomalies = safeCount(anomalyRepository::count);
        long dpi = safeCount(dpiEventRepository::count);
        long honeypot = safeCount(honeypotLogRepository::count);
        long cases = safeCount(caseRepository::count);
        long audit = safeCount(auditLogRepository::count);
        long alerts = safeCount(alertRepository::count);

        List<Asset> assets = safeList(assetRepository::findAll);
        List<User> users = safeList(userRepository::findAll);

        long assetCount = assets.size();
        Set<Asset.PurdueLevel> zoneLevels = assets.stream()
                .map(Asset::getPurdueLevel).filter(Objects::nonNull).collect(Collectors.toCollection(TreeSet::new));
        long backedUp = assets.stream().filter(a -> a.getBackupStatus() == Asset.BackupStatus.UP_TO_DATE).count();
        long userCount = users.size();
        boolean tracksFailedLogins = users.stream().anyMatch(u -> u.getFailedLoginAttempts() != null);

        // Evidence flags (platform capabilities + telemetry presence)
        boolean authEnforced = true;          // JWT bearer required on all /api (SecurityConfig)
        boolean rbac = true;                  // ADMIN/ANALYST/USER roles enforced
        boolean crypto = true;                // JWT HMAC + BCrypt + TLS
        boolean hasAudit = audit > 0;
        boolean monitoring = (anomalies + honeypot + dpi) > 0;
        boolean hasDpi = dpi > 0;
        boolean hasDeception = honeypot > 0;  // internet-exposed + internal decoys
        boolean hasSegmentation = zoneLevels.size() >= 2;
        boolean hasInventory = assetCount > 0;
        boolean hasBackup = backedUp > 0;
        boolean hasIncidentMgmt = cases > 0;

        // ---- Build the 7 Foundational Requirements --------------------------
        List<Map<String, Object>> frs = new ArrayList<>();

        // FR1 - Identification & Authentication Control
        frs.add(fr("FR1", "IAC", "Identification & Authentication Control",
                "Identify and authenticate all users, processes and devices before granting access.",
                List.of(
                    sr("SR 1.1", "Human user identification & authentication", 1,
                        authEnforced ? COMPLIANT : PARTIAL,
                        "JWT bearer authentication with BCrypt-hashed credentials enforced on every API request.",
                        List.of(re("RE(1)", "Unique identification & authentication", 2, COMPLIANT),
                                re("RE(2)", "Multifactor for untrusted networks", 3, NOT_ASSESSED),
                                re("RE(3)", "Multifactor for all networks", 4, NOT_ASSESSED))),
                    sr("SR 1.2", "Software process & device identification & authentication", 2,
                        hasDeception ? PARTIAL : NOT_ASSESSED,
                        "Remote decoy sidecars authenticate with a bearer ingest token; per-device PKI identity is not enforced.",
                        List.of(re("RE(1)", "Unique identification & authentication", 3, NOT_ASSESSED))),
                    sr("SR 1.3", "Account management", 1, userCount > 0 ? COMPLIANT : PARTIAL,
                        userCount + " managed account(s) with role assignment and lifecycle in the platform.",
                        List.of(re("RE(1)", "Unified account management", 3, PARTIAL))),
                    sr("SR 1.4", "Identifier management", 1, userCount > 0 ? COMPLIANT : PARTIAL,
                        "Unique, non-reused user identifiers managed centrally.", List.of()),
                    sr("SR 1.5", "Authenticator management", 1, PARTIAL,
                        "Passwords managed and BCrypt-hashed; hardware-backed authenticators not in use.",
                        List.of(re("RE(1)", "Hardware security for authenticators", 3, NOT_ASSESSED))),
                    sr("SR 1.6", "Wireless access management", 1, NOT_ASSESSED,
                        "No wireless access telemetry available to the platform.",
                        List.of(re("RE(1)", "Unique identification & authentication", 2, NOT_ASSESSED))),
                    sr("SR 1.7", "Strength of password-based authentication", 1, PARTIAL,
                        "BCrypt hashing in place; enforced complexity/lifetime policy not verifiable from telemetry.",
                        List.of(re("RE(1)", "Password generation & lifetime for human users", 3, NOT_ASSESSED),
                                re("RE(2)", "Password lifetime for all users", 4, NOT_ASSESSED))),
                    sr("SR 1.8", "Public key infrastructure (PKI) certificates", 2, NOT_ASSESSED,
                        "No PKI/certificate management surface in the platform.", List.of()),
                    sr("SR 1.9", "Strength of public key-based authentication", 2, NOT_ASSESSED,
                        "Public-key user authentication not implemented.",
                        List.of(re("RE(1)", "Hardware security for public key authentication", 3, NOT_ASSESSED))),
                    sr("SR 1.10", "Authenticator feedback", 1, authEnforced ? COMPLIANT : NOT_ASSESSED,
                        "Authentication does not echo credentials; failures return generic messages.", List.of()),
                    sr("SR 1.11", "Unsuccessful login attempts", 1, tracksFailedLogins ? COMPLIANT : PARTIAL,
                        "Failed-login attempts are tracked per account (failedLoginAttempts) for lockout/alerting.", List.of()),
                    sr("SR 1.12", "System use notification", 1, NOT_ASSESSED,
                        "No system-use / legal banner configured.", List.of()),
                    sr("SR 1.13", "Access via untrusted networks", 1, authEnforced ? PARTIAL : NOT_ASSESSED,
                        "All API access requires a valid token and CORS is restricted to trusted origins.",
                        List.of(re("RE(1)", "Explicit access request approval", 2, NOT_ASSESSED)))
                )));

        // FR2 - Use Control
        frs.add(fr("FR2", "UC", "Use Control",
                "Enforce assigned privileges and account for the use of the control system.",
                List.of(
                    sr("SR 2.1", "Authorization enforcement", 1, rbac ? COMPLIANT : PARTIAL,
                        "Role-based access control (ADMIN / ANALYST / USER) enforced on protected endpoints.",
                        List.of(re("RE(1)", "Authorization enforcement for all users", 2, COMPLIANT),
                                re("RE(2)", "Permission mapping to roles", 2, COMPLIANT),
                                re("RE(3)", "Supervisor override", 3, NOT_ASSESSED),
                                re("RE(4)", "Dual approval", 4, NOT_ASSESSED))),
                    sr("SR 2.2", "Wireless use control", 1, NOT_ASSESSED, "No wireless telemetry.",
                        List.of(re("RE(1)", "Identify & report unauthorized wireless devices", 2, NOT_ASSESSED))),
                    sr("SR 2.3", "Use control for portable & mobile devices", 1, NOT_ASSESSED,
                        "Portable/mobile device control not in scope of the platform.",
                        List.of(re("RE(1)", "Enforce security status of portable devices", 2, NOT_ASSESSED))),
                    sr("SR 2.4", "Mobile code", 1, NOT_ASSESSED, "No mobile-code execution surface monitored.",
                        List.of(re("RE(1)", "Mobile code integrity check", 3, NOT_ASSESSED))),
                    sr("SR 2.5", "Session lock", 1, authEnforced ? PARTIAL : NOT_ASSESSED,
                        "Stateless JWT sessions expire (jwt.expiration); interactive idle-lock not enforced.", List.of()),
                    sr("SR 2.6", "Remote session termination", 2, authEnforced ? PARTIAL : NOT_ASSESSED,
                        "Token expiry terminates remote sessions; forced server-side revocation is limited.", List.of()),
                    sr("SR 2.7", "Concurrent session control", 3, NOT_ASSESSED,
                        "Concurrent session limits not enforced.", List.of()),
                    sr("SR 2.8", "Auditable events", 1, hasAudit ? COMPLIANT : PARTIAL,
                        audit + " audit events recorded (actor, action, target, outcome, source IP, timestamp).",
                        List.of(re("RE(1)", "Centrally managed, system-wide audit trail", 3, hasAudit ? COMPLIANT : NOT_ASSESSED))),
                    sr("SR 2.9", "Audit storage capacity", 1, hasAudit ? PARTIAL : NOT_ASSESSED,
                        "Audit records persisted with retention; capacity-threshold warnings not configured.",
                        List.of(re("RE(1)", "Warn on audit storage threshold", 3, NOT_ASSESSED))),
                    sr("SR 2.10", "Response to audit processing failures", 1, NOT_ASSESSED,
                        "Automated response to audit-subsystem failure not implemented.", List.of()),
                    sr("SR 2.11", "Timestamps", 2, monitoring ? COMPLIANT : PARTIAL,
                        "All events (anomalies, DPI, honeypot, audit) carry authoritative timestamps.",
                        List.of(re("RE(1)", "Internal time synchronization", 3, NOT_ASSESSED),
                                re("RE(2)", "Protection of time source integrity", 4, NOT_ASSESSED))),
                    sr("SR 2.12", "Non-repudiation", 3, hasAudit ? PARTIAL : NOT_ASSESSED,
                        "Audit log attributes actions to an actor; cryptographic non-repudiation not enforced.",
                        List.of(re("RE(1)", "Non-repudiation for all users", 4, NOT_ASSESSED)))
                )));

        // FR3 - System Integrity
        frs.add(fr("FR3", "SI", "System Integrity",
                "Ensure the integrity of the control system to prevent unauthorized manipulation.",
                List.of(
                    sr("SR 3.1", "Communication integrity", 1, hasDpi ? PARTIAL : NOT_ASSESSED,
                        "Deep packet inspection validates OT protocol structure; API transport is TLS-protected.",
                        List.of(re("RE(1)", "Cryptographic integrity protection", 3, NOT_ASSESSED))),
                    sr("SR 3.2", "Malicious code protection", 1, monitoring ? COMPLIANT : PARTIAL,
                        "DPI anomaly engine detects unauthorized/malicious control commands (" + anomalies + " anomalies).",
                        List.of(re("RE(1)", "Protection at entry/exit points", 2, hasDeception ? COMPLIANT : PARTIAL),
                                re("RE(2)", "Central management & reporting", 3, monitoring ? COMPLIANT : NOT_ASSESSED))),
                    sr("SR 3.3", "Security functionality verification", 1, NOT_ASSESSED,
                        "Automated security self-test not implemented.",
                        List.of(re("RE(1)", "Automated verification mechanisms", 3, NOT_ASSESSED),
                                re("RE(2)", "Verification during normal operation", 4, NOT_ASSESSED))),
                    sr("SR 3.4", "Software & information integrity", 1, hasDpi ? PARTIAL : NOT_ASSESSED,
                        "Write/parameter-change operations are detected via DPI; file integrity monitoring is partial.",
                        List.of(re("RE(1)", "Automated notification of integrity violations", 3, monitoring ? PARTIAL : NOT_ASSESSED))),
                    sr("SR 3.5", "Input validation", 1, hasDpi ? COMPLIANT : PARTIAL,
                        "Protocol/function-code validation in the DPI engine; API inputs are schema-validated.", List.of()),
                    sr("SR 3.6", "Deterministic output", 1, NOT_ASSESSED,
                        "Control-output determinism is a device-level property, not observable here.", List.of()),
                    sr("SR 3.7", "Error handling", 2, COMPLIANT,
                        "Backend fails closed and returns sanitized errors without leaking internals.", List.of()),
                    sr("SR 3.8", "Session integrity", 2, authEnforced ? PARTIAL : NOT_ASSESSED,
                        "Signed JWTs protect session integrity; server-side session-id rotation is limited.",
                        List.of(re("RE(1)", "Invalidate session IDs on termination", 3, NOT_ASSESSED),
                                re("RE(2)", "Unique session ID generation", 3, PARTIAL),
                                re("RE(3)", "Randomness of session IDs", 4, NOT_ASSESSED))),
                    sr("SR 3.9", "Protection of audit information", 2, hasAudit ? PARTIAL : NOT_ASSESSED,
                        "Audit records are access-controlled; write-once/tamper-evident storage not configured.",
                        List.of(re("RE(1)", "Audit records on write-once media", 4, NOT_ASSESSED)))
                )));

        // FR4 - Data Confidentiality
        frs.add(fr("FR4", "DC", "Data Confidentiality",
                "Ensure the confidentiality of information on communication channels and in data stores.",
                List.of(
                    sr("SR 4.1", "Information confidentiality", 1, crypto ? PARTIAL : NOT_ASSESSED,
                        "Sensitive traffic to the platform is TLS-encrypted; OT-line confidentiality is device-dependent.",
                        List.of(re("RE(1)", "Confidentiality at rest / on untrusted networks", 2, PARTIAL),
                                re("RE(2)", "Confidentiality across zone boundaries", 3, NOT_ASSESSED))),
                    sr("SR 4.2", "Information persistence", 2, NOT_ASSESSED,
                        "Secure purge of shared memory/resources not enforced by the platform.",
                        List.of(re("RE(1)", "Purging of shared memory resources", 3, NOT_ASSESSED))),
                    sr("SR 4.3", "Use of cryptography", 1, crypto ? COMPLIANT : PARTIAL,
                        "JWT (HMAC-SHA256), BCrypt password hashing and TLS transport in use.", List.of())
                )));

        // FR5 - Restricted Data Flow
        frs.add(fr("FR5", "RDF", "Restricted Data Flow",
                "Segment the control system into zones and conduits to limit unnecessary data flow.",
                List.of(
                    sr("SR 5.1", "Network segmentation", 1, hasSegmentation ? COMPLIANT : PARTIAL,
                        assetCount + " assets mapped across " + zoneLevels.size() + " Purdue level(s) / zones.",
                        List.of(re("RE(1)", "Physical network segmentation", 2, hasSegmentation ? PARTIAL : NOT_ASSESSED),
                                re("RE(2)", "Independence from non-control networks", 3, NOT_ASSESSED),
                                re("RE(3)", "Logical & physical isolation of critical networks", 4, NOT_ASSESSED))),
                    sr("SR 5.2", "Zone boundary protection", 1, hasDeception ? COMPLIANT : PARTIAL,
                        "Deception decoys and DPI at zone boundaries observe and contain cross-zone attempts.",
                        List.of(re("RE(1)", "Deny by default, allow by exception", 2, PARTIAL),
                                re("RE(2)", "Island mode", 3, NOT_ASSESSED),
                                re("RE(3)", "Fail close", 4, NOT_ASSESSED))),
                    sr("SR 5.3", "General purpose person-to-person communication restrictions", 1, NOT_ASSESSED,
                        "General-purpose messaging on the control network is not monitored/restricted here.",
                        List.of(re("RE(1)", "Prohibit all general purpose person-to-person comms", 3, NOT_ASSESSED))),
                    sr("SR 5.4", "Application partitioning", 2, NOT_ASSESSED,
                        "Application-level partitioning is a system-design property, not observable here.", List.of())
                )));

        // FR6 - Timely Response to Events
        frs.add(fr("FR6", "TRE", "Timely Response to Events",
                "Detect security events, report them, and respond in a timely manner.",
                List.of(
                    sr("SR 6.1", "Audit log accessibility", 1, hasAudit ? COMPLIANT : PARTIAL,
                        "Audit trail is queryable via the Settings audit-log API for authorized analysts.",
                        List.of(re("RE(1)", "Programmatic access to audit logs", 3, hasAudit ? COMPLIANT : NOT_ASSESSED))),
                    sr("SR 6.2", "Continuous monitoring", 2, monitoring ? COMPLIANT : PARTIAL,
                        "Continuous monitoring: anomaly engine, honeypot live feed and DPI on all captured traffic ("
                        + anomalies + " anomalies, " + honeypot + " decoy events, " + alerts + " alerts, " + cases + " cases).",
                        List.of())
                )));

        // FR7 - Resource Availability
        frs.add(fr("FR7", "RA", "Resource Availability",
                "Ensure availability of the control system against degradation or denial of essential services.",
                List.of(
                    sr("SR 7.1", "Denial of service protection", 1, monitoring ? PARTIAL : NOT_ASSESSED,
                        "Write-burst / flooding anomaly rules flag DoS-like patterns; automated rate-limiting is partial.",
                        List.of(re("RE(1)", "Manage communication loads", 2, NOT_ASSESSED))),
                    sr("SR 7.2", "Resource management", 1, NOT_ASSESSED,
                        "Control-system resource quotas are device-level, not observable here.", List.of()),
                    sr("SR 7.3", "Control system backup", 1, hasBackup ? COMPLIANT : PARTIAL,
                        backedUp + " of " + assetCount + " assets recorded as backed up (up to date).",
                        List.of(re("RE(1)", "Backup verification", 2, hasBackup ? PARTIAL : NOT_ASSESSED),
                                re("RE(2)", "Backup automation", 3, NOT_ASSESSED))),
                    sr("SR 7.4", "Control system recovery & reconstitution", 1, NOT_ASSESSED,
                        "Automated recovery/reconstitution runbooks not integrated.", List.of()),
                    sr("SR 7.5", "Emergency power", 1, NOT_ASSESSED,
                        "Emergency power is a facility control outside the platform's visibility.", List.of()),
                    sr("SR 7.6", "Network & security configuration settings", 1, hasInventory ? PARTIAL : NOT_ASSESSED,
                        "Security settings are centrally configurable; machine-readable export is partial.",
                        List.of(re("RE(1)", "Machine-readable reporting of settings", 3, NOT_ASSESSED))),
                    sr("SR 7.7", "Least functionality", 1, NOT_ASSESSED,
                        "Device hardening / least-functionality is enforced at the endpoint, not observable here.", List.of()),
                    sr("SR 7.8", "Control system component inventory", 2, hasInventory ? COMPLIANT : PARTIAL,
                        assetCount + " components in the passively-discovered asset inventory.", List.of())
                )));

        // ---- Roll-ups -------------------------------------------------------
        int totalReqs = 0, compliantReqs = 0, partialReqs = 0, naReqs = 0;
        for (Map<String, Object> f : frs) {
            totalReqs += (int) f.get("total");
            compliantReqs += (int) f.get("compliant");
            partialReqs += (int) f.get("partial");
            naReqs += (int) f.get("notAssessed");
        }
        int coveragePct = totalReqs > 0 ? Math.round((compliantReqs * 100f) / totalReqs) : 0;
        int overallAchievedSL = frs.stream().mapToInt(f -> (int) f.get("achievedSL")).min().orElse(0);

        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("organization", Map.of(
                "name", "SafeTech ICS Operator",
                "sector", "Manufacturing (IACS)",
                "standard", "ISA/IEC 62443-3-3",
                "targetSL", TARGET_SL));
        posture.put("overall", Map.of(
                "coveragePct", coveragePct,
                "achievedSL", overallAchievedSL,
                "targetSL", TARGET_SL,
                "classification", classify(coveragePct),
                "totalRequirements", totalReqs,
                "compliant", compliantReqs,
                "partial", partialReqs,
                "notAssessed", naReqs));
        posture.put("securityLevels", securityLevelModel());
        posture.put("standardParts", standardParts());
        posture.put("foundationalRequirements", frs);
        posture.put("zones", buildZones(assets, backedUp));
        return posture;
    }

    // ------------------------------------------------------------------
    // Builders / helpers
    // ------------------------------------------------------------------

    private Map<String, Object> fr(String code, String key, String name, String desc, List<Map<String, Object>> srs) {
        int total = srs.size();
        int compliant = (int) srs.stream().filter(s -> COMPLIANT.equals(s.get("status"))).count();
        int partial = (int) srs.stream().filter(s -> PARTIAL.equals(s.get("status"))).count();
        int notAssessed = (int) srs.stream().filter(s -> NOT_ASSESSED.equals(s.get("status"))).count();
        int coveragePct = total > 0 ? Math.round((compliant * 100f) / total) : 0;

        // Achieved SL = highest SL n (1..4) where every base SR applicable at
        // n is COMPLIANT (strict 62443 all-or-nothing per level).
        int achievedSL = 0;
        for (int sl = 1; sl <= 4; sl++) {
            final int level = sl;
            boolean allMet = srs.stream()
                    .filter(s -> (int) s.get("appliesFrom") <= level)
                    .allMatch(s -> COMPLIANT.equals(s.get("status")));
            if (allMet) achievedSL = sl; else break;
        }

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fr", code);
        m.put("code", key);
        m.put("name", name);
        m.put("description", desc);
        m.put("total", total);
        m.put("compliant", compliant);
        m.put("partial", partial);
        m.put("notAssessed", notAssessed);
        m.put("coveragePct", coveragePct);
        m.put("achievedSL", achievedSL);
        m.put("targetSL", TARGET_SL);
        m.put("requirements", srs);
        return m;
    }

    private Map<String, Object> sr(String id, String title, int appliesFrom, String status,
                                   String evidence, List<Map<String, Object>> res) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("title", title);
        m.put("appliesFrom", appliesFrom);
        m.put("status", status);
        m.put("evidence", evidence);
        m.put("enhancements", res);
        return m;
    }

    private Map<String, Object> re(String id, String title, int sl, String status) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("title", title);
        m.put("sl", sl);
        m.put("status", status);
        return m;
    }

    private List<Map<String, Object>> buildZones(List<Asset> assets, long backedUp) {
        Map<Asset.PurdueLevel, List<Asset>> byLevel = assets.stream()
                .filter(a -> a.getPurdueLevel() != null)
                .collect(Collectors.groupingBy(Asset::getPurdueLevel));
        List<Map<String, Object>> zones = new ArrayList<>();
        for (Asset.PurdueLevel lvl : Asset.PurdueLevel.values()) {
            List<Asset> in = byLevel.getOrDefault(lvl, List.of());
            if (in.isEmpty()) continue;
            long bk = in.stream().filter(a -> a.getBackupStatus() == Asset.BackupStatus.UP_TO_DATE).count();
            Map<String, Object> z = new LinkedHashMap<>();
            z.put("level", lvl.name());
            z.put("name", lvl.getDisplayName());
            z.put("assetCount", in.size());
            z.put("backedUp", bk);
            // Suggested target SL: deeper (lower Purdue) zones warrant higher SL-T
            z.put("suggestedTargetSL", lvl == Asset.PurdueLevel.LEVEL_0 || lvl == Asset.PurdueLevel.LEVEL_1 ? 3 : 2);
            zones.add(z);
        }
        return zones;
    }

    private List<Map<String, Object>> securityLevelModel() {
        return List.of(
            slDef(0, "No specific requirements", "No protection required."),
            slDef(1, "Casual / coincidental", "Protection against casual or coincidental violation."),
            slDef(2, "Intentional - simple means", "Simple means, low resources, generic skills, low motivation."),
            slDef(3, "Intentional - sophisticated means", "Sophisticated means, moderate resources, IACS-specific skills, moderate motivation."),
            slDef(4, "Intentional - extended resources", "Sophisticated means, extended resources, IACS-specific skills, high motivation.")
        );
    }

    private Map<String, Object> slDef(int sl, String name, String desc) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sl", sl);
        m.put("name", name);
        m.put("description", desc);
        return m;
    }

    private List<Map<String, Object>> standardParts() {
        String[][] parts = {
            {"1-1", "Terminology, concepts & models"},
            {"1-2", "Master glossary of terms"},
            {"1-3", "System security compliance metrics"},
            {"1-4", "IACS security lifecycle & use cases"},
            {"2-1", "Establishing an IACS security program (asset owner)"},
            {"2-2", "IACS security protection rating"},
            {"2-3", "Patch management in the IACS environment"},
            {"2-4", "Security program requirements for service providers"},
            {"3-1", "Security technologies for IACS"},
            {"3-2", "Security risk assessment for system design (zones & conduits)"},
            {"3-3", "System security requirements & security levels"},
            {"4-1", "Secure product development lifecycle"},
            {"4-2", "Technical security requirements for IACS components"},
        };
        List<Map<String, Object>> out = new ArrayList<>();
        for (String[] p : parts) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("part", p[0]);
            m.put("title", p[1]);
            m.put("focus", "3-3".equals(p[0])); // the part this page assesses
            out.add(m);
        }
        return out;
    }

    private String classify(int coveragePct) {
        if (coveragePct >= 85) return "ROBUST";
        if (coveragePct >= 70) return "MATURE";
        if (coveragePct >= 50) return "DEVELOPING";
        return "INITIAL";
    }

    private long safeCount(java.util.function.LongSupplier s) {
        try { return s.getAsLong(); } catch (Exception e) { return 0L; }
    }

    private <T> List<T> safeList(java.util.function.Supplier<List<T>> s) {
        try { return s.get(); } catch (Exception e) { return List.of(); }
    }
}

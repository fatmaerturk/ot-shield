package com.safetech.otshield.dto;

import java.time.LocalDateTime;

/**
 * Lightweight read-only projection of {@code honeypot_logs} carrying only the
 * columns the TTP analysis needs. It deliberately omits the heavy {@code payload}
 * TEXT column (TTP never reads it), so the all-time scan hydrates far less data
 * per row - which shrinks the allocation (and the GC pause) of the periodic
 * TTP recompute without changing a single displayed figure.
 *
 * Getter names mirror {@link com.safetech.otshield.model.HoneypotLog} exactly so
 * the existing TTP code (method references, field access) works unchanged.
 */
public class TtpLogRow {

    private final String sourceIp;
    private final String attackType;
    private final LocalDateTime timestamp;
    private final String description;
    private final String protocol;
    private final String usernameAttempt;
    private final String userAgent;
    private final String passwordAttempt;
    private final String severity;
    private final String country;
    private final String decoySource;

    /** Argument order MUST match the JPQL constructor expression in
     *  {@code HoneypotLogRepository.findTtpRows()}. */
    public TtpLogRow(String sourceIp, String attackType, LocalDateTime timestamp, String description,
                     String protocol, String usernameAttempt, String userAgent, String passwordAttempt,
                     String severity, String country, String decoySource) {
        this.sourceIp = sourceIp;
        this.attackType = attackType;
        this.timestamp = timestamp;
        this.description = description;
        this.protocol = protocol;
        this.usernameAttempt = usernameAttempt;
        this.userAgent = userAgent;
        this.passwordAttempt = passwordAttempt;
        this.severity = severity;
        this.country = country;
        this.decoySource = decoySource;
    }

    public String getSourceIp() { return sourceIp; }
    public String getAttackType() { return attackType; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getDescription() { return description; }
    public String getProtocol() { return protocol; }
    public String getUsernameAttempt() { return usernameAttempt; }
    public String getUserAgent() { return userAgent; }
    public String getPasswordAttempt() { return passwordAttempt; }
    public String getSeverity() { return severity; }
    public String getCountry() { return country; }
    public String getDecoySource() { return decoySource; }
}

package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * One firing of a honeytoken: an intruder used the planted lure. Each trip is a
 * high-confidence breach event - legitimate users never touch these.
 */
@Entity
@Table(name = "honeytoken_trip")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class HoneytokenTrip {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "token_id", length = 64)
    private String tokenId;

    @Column(name = "token_label")
    private String tokenLabel;

    @Column(name = "token_type", length = 32)
    private String tokenType;

    /** CALLBACK (beacon hit) or CREDENTIAL_REPLAY (secret seen in telemetry). */
    @Column(name = "method", length = 32)
    private String method;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "detail", columnDefinition = "TEXT")
    private String detail;

    @Column(name = "ts")
    private Instant ts;
}

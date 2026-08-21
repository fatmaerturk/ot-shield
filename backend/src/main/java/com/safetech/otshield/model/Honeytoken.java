package com.safetech.otshield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * A honeytoken (decoy lure) planted in the real environment - a fake credential,
 * API key, connection string, bookmark URL or document beacon that no legitimate
 * user has any reason to touch. When one is used or opened it fires a
 * high-confidence breach signal, because the only actor who reaches it is an
 * intruder who found it while poking around. This turns the deception fabric from
 * a passive trap into an active lure.
 *
 * Two real trip mechanisms:
 *  - CALLBACK: a planted URL/beacon is hit -> the hit endpoint records the real
 *    source IP + user agent + time.
 *  - CREDENTIAL_REPLAY: a planted secret shows up in captured decoy telemetry
 *    (an attacker harvested it and replayed it against the decoy fabric).
 */
@Entity
@Table(name = "honeytoken")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Honeytoken {

    @Id
    @Column(name = "id", length = 64)
    private String id;

    /** CREDENTIAL, API_KEY, CONNECTION_STRING, URL_BEACON, FILE_BEACON. */
    @Column(name = "type", length = 32)
    private String type;

    /** Where the operator planted it, e.g. "ENG-WKSTN-01 / Desktop". */
    @Column(name = "label")
    private String label;

    @Column(name = "note", columnDefinition = "TEXT")
    private String note;

    /** The plant payload the operator drops into the environment. */
    @Column(name = "token_value", columnDefinition = "TEXT")
    private String tokenValue;

    /**
     * The unique string to correlate against captured decoy telemetry (a
     * username or key). Null for pure beacon tokens that only trip via callback.
     */
    @Column(name = "match_value")
    private String matchValue;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "trips")
    private int trips;

    @Column(name = "last_tripped_at")
    private Instant lastTrippedAt;

    @Column(name = "last_source_ip")
    private String lastSourceIp;
}

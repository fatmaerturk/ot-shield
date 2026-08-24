package com.safetech.otshield.dto.attacker;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** One step in an attacker's stitched kill-chain timeline. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TimelineEventDTO {
    private LocalDateTime timestamp;
    /** HONEYPOT | TWIN | DPI | ANOMALY | CASE */
    private String source;
    private KillChainPhase phase;
    private String title;
    private String description;
    private String protocol;
    private String functionCode;
    private String targetIp;
    private String targetAsset;
    private String mitreId;
    private String mitreTechnique;
    /** CRITICAL | HIGH | MEDIUM | LOW | INFO */
    private String severity;
    /** id of the underlying anomaly / case / event, when one exists. */
    private String refId;
}

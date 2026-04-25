package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.time.Instant;

/**
 * A single decoy/honeypot instance in the deception fabric.
 * Represents one industrial-protocol decoy persona deployed at a given IP/port.
 */
@Data
public class DecoyInstanceDTO {
    private String id;
    private String name;
    private DecoyEnums.DecoyProtocol protocol;
    private String vendor;
    private String model;
    private String firmware;
    private String ipAddress;
    private Integer port;
    private Integer purdueLevel;          // 1, 2, or 3
    private DecoyEnums.DecoyStatus status;
    private Long uptimeSeconds;
    private Long totalEngagements;
    private Long activeEngagements;
    private Instant lastEngagementAt;
    private Integer threatScore;          // 0..100, rolled up from active attackers
    private String description;           // free-form persona description (e.g. "Wastewater RTU")
    private String facility;              // logical site label, e.g. "Plant-A"
    private Double facilityX;             // 0..1 normalised x within the facility floor (for topology map)
    private Double facilityY;             // 0..1 normalised y
}

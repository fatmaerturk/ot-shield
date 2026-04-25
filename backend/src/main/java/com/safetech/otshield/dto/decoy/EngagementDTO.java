package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.time.Instant;
import java.util.List;

/**
 * An attacker session against one decoy instance.
 * The list endpoint returns this without `events`/`attackerProfile` populated;
 * the detail endpoint fills them in.
 */
@Data
public class EngagementDTO {
    private String id;
    private String decoyInstanceId;
    private String decoyName;
    private DecoyEnums.DecoyProtocol protocol;
    private String attackerIp;
    private String attackerCountry;       // ISO-2
    private String attackerAsn;
    private Instant startedAt;
    private Instant lastActivityAt;
    private Instant endedAt;              // null while ACTIVE
    private DecoyEnums.EngagementStatus status;
    private DecoyEnums.Severity severity;
    private Integer threatScore;          // 0..100
    private Long eventCount;
    private List<MitreTtpDTO> mitreTtps;  // unique TTPs observed in this engagement
    private List<EngagementEventDTO> events;       // populated on detail
    private AttackerProfileDTO attackerProfile;    // populated on detail
}

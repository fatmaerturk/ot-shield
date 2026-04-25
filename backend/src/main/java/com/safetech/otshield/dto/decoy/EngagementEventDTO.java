package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.time.Instant;

/**
 * One protocol message exchanged within an engagement.
 * The deep payload view powers the SOC's "Replay & Inspect" panel.
 */
@Data
public class EngagementEventDTO {
    private String id;
    private String engagementId;
    private Instant ts;
    private DecoyEnums.EventDirection direction;
    private DecoyEnums.Severity severity;
    private String summary;          // e.g. "Read 10 holding registers from PLC"
    private MitreTtpDTO mitre;       // optional
    private PayloadDeepDTO payload;  // deep parsed view (may be null for keepalives)
}

package com.safetech.otshield.dto.decoy;

import lombok.Data;

/** MITRE ATT&CK for ICS technique reference attached to engagements/events. */
@Data
public class MitreTtpDTO {
    private String tactic;        // e.g. "Discovery", "Impair Process Control"
    private String techniqueId;   // e.g. "T0846"
    private String techniqueName; // e.g. "Remote System Discovery"
    private Integer confidence;   // 0..100
}

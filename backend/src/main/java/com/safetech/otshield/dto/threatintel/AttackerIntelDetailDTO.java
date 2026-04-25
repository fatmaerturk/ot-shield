package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.util.List;

/**
 * Full attacker intel view: summary + filled ATT&CK matrix + fingerprint +
 * related engagements (ids) + campaign cluster membership.
 */
@Data
public class AttackerIntelDetailDTO {
    private AttackerIntelSummaryDTO summary;
    private TtpMatrixDTO ttpMatrix;                // techniques filled with hit data for this attacker
    private BehavioralFingerprintDTO fingerprint;
    private List<String> engagementIds;            // ids we can cross-ref
    private List<CampaignClusterDTO> campaigns;    // clusters this attacker belongs to
    private List<String> relatedIps;               // IPs in the same campaign
    private List<String> iocHighlights;            // e.g. "AS14061 reused", "raw S7 DB write on DB42"
}

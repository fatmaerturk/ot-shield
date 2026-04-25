package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.util.List;

/** Request payload for /api/threat-intel/export */
@Data
public class IocExportRequest {
    private String format;              // "STIX" | "CSV" | "PLAIN"
    private List<String> attackerIps;   // subset; empty -> all known
    private Boolean includeCampaigns;   // default true
    private Boolean includeTtps;        // default true
}

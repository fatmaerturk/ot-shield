package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.util.List;

/** Mock TAXII/MISP push request. */
@Data
public class IntelPushRequest {
    private String target;            // "TAXII" | "MISP" | "SIEM"
    private String endpoint;          // optional URL label
    private List<String> attackerIps; // what to push
    private String reason;            // analyst note
}

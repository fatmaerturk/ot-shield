package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.time.Instant;

@Data
public class IntelPushResultDTO {
    private String id;
    private String target;
    private String status;          // "ACCEPTED" | "FAILED"
    private Instant pushedAt;
    private Integer pushedIocs;
    private String externalRef;     // e.g. "misp-event-1024"
    private String message;
}

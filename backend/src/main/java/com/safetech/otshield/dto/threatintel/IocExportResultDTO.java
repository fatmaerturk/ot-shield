package com.safetech.otshield.dto.threatintel;

import lombok.Data;
import java.time.Instant;

@Data
public class IocExportResultDTO {
    private String id;                 // export id (for replay)
    private String format;             // STIX | CSV | PLAIN
    private Instant generatedAt;
    private Integer iocCount;
    private String content;            // the export body itself (json/csv/plain)
    private String filename;           // suggested filename
}

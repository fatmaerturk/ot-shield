package com.safetech.otshield.dto.fakehmi;

import lombok.Data;
import java.time.Instant;

/**
 * Alarm row displayed on a fake HMI alarm strip / alarm summary page.
 */
@Data
public class HmiAlarmDTO {
    private String id;
    private FakeHmiEnums.HmiAlarmSeverity severity;
    private String tag;            // metric key this alarm is attached to, if any
    private String message;
    private Instant ts;
    private Boolean acknowledged;
    private String source;         // e.g. "ProcessControl", "Safety", "SCADA"
}

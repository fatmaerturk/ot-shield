package com.safetech.otshield.dto.fakehmi;

import lombok.Data;

/**
 * Rollup stats for the Fake HMIs header widgets.
 */
@Data
public class FakeHmiStatsDTO {
    private Integer totalHmis;
    private Integer runningHmis;
    private Integer activeAlarms;
    private Long interactions24h;
    private Integer distinctAttackers24h;
    private FakeHmiEnums.HmiScenarioType mostTargetedScenario;
}

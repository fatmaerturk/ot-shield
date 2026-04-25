package com.safetech.otshield.dto.fakehmi;

import lombok.Data;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A single fake HMI deployed in the deception layer. Carries its live
 * process snapshot (metrics + active alarms) plus interaction counters.
 */
@Data
public class FakeHmiInstanceDTO {
    private String id;
    private String name;                     // "Water Plant North HMI-02"
    private FakeHmiEnums.HmiScenarioType scenario;
    private FakeHmiEnums.HmiVariantStyle variant;
    private FakeHmiEnums.HmiStatus status;

    // Persona
    private String vendor;                   // "Siemens", "Rockwell Automation", "Schneider Electric", "ABB"
    private String model;                    // "SIMATIC WinCC OA", "FactoryTalk View SE", "EcoStruxure Operator Terminal", ...
    private String firmware;                 // "V17 SP1", "11.00.00", ...
    private String ipAddress;
    private Integer port;                    // 80 / 443 / 502 depending
    private Integer purdueLevel;             // typically 2
    private String facility;                 // logical site
    private Double facilityX;                // 0..1 location on facility map
    private Double facilityY;

    // Live data
    private List<HmiMetricDTO> metrics = new ArrayList<>();
    private List<HmiAlarmDTO> alarms = new ArrayList<>();

    // Interaction rollups
    private Long totalInteractions;          // cumulative attacker hits
    private Long interactions24h;            // rolling 24h count
    private Integer distinctAttackers24h;    // unique IPs in last 24h
    private Instant lastAccessedAt;
    private Integer threatScore;             // 0..100 heuristic
    private Long uptimeSeconds;

    // Optional: populated on detail endpoint
    private List<HmiInteractionDTO> recentInteractions = new ArrayList<>();
}

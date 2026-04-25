package com.safetech.otshield.dto.fakehmi;

import lombok.Data;

/**
 * One live process variable shown on a fake HMI screen.
 * Values drift over time; alarming flag is derived from min/max thresholds.
 */
@Data
public class HmiMetricDTO {
    private String key;          // stable id e.g. "tank1_level"
    private String name;         // display name e.g. "Tank 1 Level"
    private Double value;
    private String unit;         // "%", "°C", "bar", "kV", "A", "rpm"...
    private Double min;          // normal range low
    private Double max;          // normal range high
    private Boolean alarming;    // value < min || value > max
    private String category;     // "tank" | "pump" | "temp" | "pressure" | "flow" | "voltage" | "current" | "counter" | "gauge"
    private Integer trend;       // -1 falling, 0 flat, 1 rising (last tick)
}

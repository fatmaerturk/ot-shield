package com.safetech.otshield.dto.decoy;

import lombok.Data;

/**
 * One semantic field inside a deeply-parsed payload.
 * Examples:
 *   - Modbus:   { name: "Holding Register 40001", value: "0x00FA" (250),    flagged: true }
 *   - S7:       { name: "DB1.DBW10",              value: "1500",            flagged: false }
 *   - OPC UA:   { name: "ns=2;s=Pump1.Speed",     value: "0",               flagged: true }
 *   - DNP3:     { name: "Object 12 Var 1 Index 0",value: "Cold Restart",    flagged: true }
 */
@Data
public class PayloadFieldDTO {
    private String name;       // human-readable address / register / node id
    private String type;       // "REGISTER" | "COIL" | "DB" | "NODE" | "OBJECT" | ...
    private String value;      // decoded value
    private String rawHex;     // optional raw bytes
    private String unit;       // optional engineering unit (RPM, °C, bar, ...)
    private Boolean flagged;   // true if this specific field tripped an anomaly rule
    private String anomalyReason; // free-form explanation when flagged
}

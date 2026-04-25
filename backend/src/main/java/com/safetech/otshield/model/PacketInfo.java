package com.safetech.otshield.model;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Data
public class PacketInfo {
    private String sourceIp;
    private String destinationIp;
    private int sourcePort;
    private int destinationPort;
    private String protocol;
    private LocalDateTime timestamp;
    private int packetLength;
    private String payloadInfo;
    private String flags;
    private int sequenceNumber;
    private int acknowledgmentNumber;
    private int windowSize;
    private String packetType;
    private String packetSummary;

    // Purdue model level information
    private String sourceLevel;  // Level 0-5: Enterprise, DMZ, Level 3, Level 2, Level 1, Level 0
    private String destinationLevel;
    private String communicationType; // Control, Monitoring, Data, Management

    // Brand and model extracted via deep packet inspection (separate for source and destination)
    private String sourceManufacturer;
    private String destinationManufacturer;
    private String sourceModel;
    private String destinationModel;

    /**
     * Protocol-specific deep-packet-inspection fields produced by dissectors.
     * Key examples (see each dissector for the complete list):
     *   Modbus:  function_code, function_name, register_address, quantity,
     *            value, unit_id, transaction_id, is_write, is_exception,
     *            exception_code
     *   S7Comm:  job_type, rosctr, function_code, function_name, area,
     *            db_number, address, length, is_write, is_plc_control
     *   IEC104:  (existing payloadInfo still carries summary)
     *
     * Kept as an insertion-ordered map so JSON serialization keeps fields in
     * a stable, human-readable order for the UI.
     */
    private Map<String, String> dpiFields = new LinkedHashMap<>();

    public PacketInfo() {
    }

    /** Convenience helper for dissectors - creates the map on first use. */
    public void putDpiField(String key, String value) {
        if (key == null || value == null) return;
        if (this.dpiFields == null) {
            this.dpiFields = new LinkedHashMap<>();
        }
        this.dpiFields.put(key, value);
    }
}
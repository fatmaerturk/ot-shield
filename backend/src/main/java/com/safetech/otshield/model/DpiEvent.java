package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * A persisted Deep-Packet-Inspection event. One row per ICS-protocol PDU
 * that {@link com.safetech.otshield.service.dpi.ModbusDissector},
 * {@link com.safetech.otshield.service.dpi.S7CommDissector} or the inline
 * IEC104 parser has successfully decoded.
 *
 * <p>Persisted DPI events let the Network Topology timeline show *real*
 * function-code activity over time (not only anomalies) and let the UI
 * answer questions like:
 * <ul>
 *   <li>"What function codes did this PLC ever receive?"</li>
 *   <li>"When did a write command from this workstation first appear?"</li>
 *   <li>"Is this function code rare on this conduit?"</li>
 * </ul>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "dpi_events", indexes = {
        @Index(name = "idx_dpi_events_time", columnList = "event_time"),
        @Index(name = "idx_dpi_events_src_dst", columnList = "source_ip, destination_ip"),
        @Index(name = "idx_dpi_events_protocol", columnList = "protocol"),
        @Index(name = "idx_dpi_events_function", columnList = "protocol, function_code"),
        @Index(name = "idx_dpi_events_session", columnList = "pcap_session_id")
})
public class DpiEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** When the packet was captured (pcap timestamp, not ingest time). */
    @Column(name = "event_time", nullable = false)
    private LocalDateTime eventTime;

    @Column(name = "source_ip", nullable = false, length = 64)
    private String sourceIp;

    @Column(name = "destination_ip", nullable = false, length = 64)
    private String destinationIp;

    @Column(name = "source_port")
    private Integer sourcePort;

    @Column(name = "destination_port")
    private Integer destinationPort;

    /** Short label: MODBUS, S7COMM, IEC104, … */
    @Column(nullable = false, length = 32)
    private String protocol;

    /** Canonical function-code tag from the dissector, e.g. "0x06", "0x05" (S7 Write Var). */
    @Column(name = "function_code", length = 16)
    private String functionCode;

    /** Human-readable name: "Write Single Register", "PLC Stop", "Setup Communication". */
    @Column(name = "function_name", length = 64)
    private String functionName;

    /** read / write / other - feeds UI coloring + anomaly rules. */
    @Column(name = "pdu_kind", length = 16)
    private String pduKind;

    @Column(name = "is_write")
    private Boolean isWrite;

    @Column(name = "is_exception")
    private Boolean isException;

    /** Modbus register address or S7 byte address (stringified for cross-protocol storage). */
    @Column(name = "register_address", length = 32)
    private String registerAddress;

    /** S7 memory area: DB, I, Q, M, T, C - null for Modbus events. */
    @Column(length = 16)
    private String area;

    /** Written value (Modbus: numeric; S7: hex prefix); truncated to 64 chars. */
    @Column(length = 64)
    private String value;

    /** Compact one-line summary (same string used in PacketInfo.payloadInfo). */
    @Column(length = 512)
    private String summary;

    /** Full dissector output serialized as JSON - for detail modal. */
    @Column(name = "dpi_fields_json", columnDefinition = "TEXT")
    private String dpiFieldsJson;

    /** Groups all events produced by a single .pcap upload. */
    @Column(name = "pcap_session_id", length = 64)
    private String pcapSessionId;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (eventTime == null) {
            eventTime = createdAt;
        }
    }
}

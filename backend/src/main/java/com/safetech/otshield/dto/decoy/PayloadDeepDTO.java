package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.util.List;

/**
 * Deeply-parsed view of a single protocol message.
 * Always carries the raw hex/ASCII so the SOC can replay or pivot,
 * plus a structured field list when the parser recognised the protocol.
 */
@Data
public class PayloadDeepDTO {
    private String protocolOp;            // e.g. "MODBUS.READ_HOLDING_REGISTERS"
    private String functionCodeHex;       // e.g. "0x03"
    private String functionCodeName;      // e.g. "Read Holding Registers"
    private Integer transactionId;        // protocol-specific transaction / sequence id
    private Integer unitId;               // Modbus unit id / S7 rack/slot / DNP3 address
    private String addressRange;          // e.g. "40001..40010"
    private Integer byteCount;
    private String rawHex;                // full payload bytes, hex-encoded
    private String rawAscii;              // best-effort ASCII rendering
    private List<PayloadFieldDTO> fields; // structured semantic breakdown
    private List<String> anomalyFlags;    // e.g. ["UNAUTHORIZED_WRITE", "OUT_OF_HOURS"]
}

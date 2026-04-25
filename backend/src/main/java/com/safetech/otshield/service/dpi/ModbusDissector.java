package com.safetech.otshield.service.dpi;

import com.safetech.otshield.model.PacketInfo;

/**
 * Deep-packet-inspection dissector for Modbus TCP (IANA port 502).
 *
 * <p>Modbus TCP frame layout (big-endian):
 * <pre>
 *   MBAP Header (7 bytes)                             PDU
 *   ┌──────────┬────────┬────────┬─────────┐  ┌───────┬────────────┐
 *   │ TxnId(2) │ Proto(2)│ Len(2) │ UnitId(1)│  │ FC(1) │ Data (...) │
 *   └──────────┴────────┴────────┴─────────┘  └───────┴────────────┘
 * </pre>
 *
 * <p>Function codes covered:
 * <ul>
 *   <li>0x01 Read Coils</li>
 *   <li>0x02 Read Discrete Inputs</li>
 *   <li>0x03 Read Holding Registers</li>
 *   <li>0x04 Read Input Registers</li>
 *   <li>0x05 Write Single Coil</li>
 *   <li>0x06 Write Single Register</li>
 *   <li>0x07 Read Exception Status</li>
 *   <li>0x0F Write Multiple Coils</li>
 *   <li>0x10 Write Multiple Registers</li>
 *   <li>0x16 Mask Write Register</li>
 *   <li>0x17 Read/Write Multiple Registers</li>
 *   <li>0x2B MEI / Encapsulated Interface (Read Device ID)</li>
 * </ul>
 *
 * <p>Exception responses (function code with high bit set: {@code fc | 0x80})
 * are also parsed; the exception code maps to a human-readable name.
 *
 * <p>The dissector populates {@link PacketInfo#getDpiFields()} and also
 * returns a compact one-line summary suitable for display in the legacy
 * {@code payloadInfo} column.
 */
public final class ModbusDissector {

    public static final int MODBUS_TCP_PORT = 502;
    public static final int MBAP_HEADER_LEN = 7;

    private ModbusDissector() {
        // Utility class
    }

    /**
     * Parse a Modbus TCP payload. Safe to call on any byte array - returns
     * {@code null} when the buffer is too short or obviously not Modbus.
     *
     * @param payload raw TCP payload bytes (starting at MBAP header)
     * @param srcPort TCP source port
     * @param dstPort TCP destination port
     * @param info    packet info to enrich (dpi fields + optional payload
     *                summary). Must not be null.
     * @return compact human-readable summary string, or {@code null} when no
     *         Modbus payload could be parsed
     */
    public static String dissect(byte[] payload, int srcPort, int dstPort, PacketInfo info) {
        if (payload == null || payload.length < MBAP_HEADER_LEN + 1 || info == null) {
            return null;
        }

        // --- MBAP header ----------------------------------------------------
        int txnId = ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF);
        int protoId = ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF);
        int length = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
        int unitId = payload[6] & 0xFF;

        // protocol_id MUST be 0 for Modbus TCP - if not, this is almost
        // certainly some other protocol happening to use port 502.
        if (protoId != 0) {
            return null;
        }
        // length field covers unit-id + PDU; must match remaining bytes ±1
        if (length <= 0 || length > payload.length - 6 + 1) {
            // Don't hard-fail on length mismatch - still try to parse PDU,
            // but flag it.
            info.putDpiField("mbap_length_mismatch", "true");
        }

        int rawFc = payload[7] & 0xFF;
        boolean isException = (rawFc & 0x80) != 0;
        int fc = rawFc & 0x7F;
        boolean isRequest = isClientToServer(srcPort, dstPort);

        info.putDpiField("transaction_id", String.valueOf(txnId));
        info.putDpiField("unit_id", String.valueOf(unitId));
        info.putDpiField("function_code", String.format("0x%02X", fc));
        info.putDpiField("function_name", functionName(fc));
        info.putDpiField("direction", isRequest ? "request" : "response");
        info.putDpiField("is_exception", String.valueOf(isException));

        StringBuilder summary = new StringBuilder();
        summary.append("Modbus: ").append(isException ? "EXCEPTION " : "").append(functionName(fc));

        // --- Exception PDU --------------------------------------------------
        if (isException) {
            if (payload.length >= MBAP_HEADER_LEN + 2) {
                int exCode = payload[8] & 0xFF;
                info.putDpiField("exception_code", String.format("0x%02X", exCode));
                info.putDpiField("exception_name", exceptionName(exCode));
                summary.append(" · code=").append(String.format("0x%02X", exCode))
                       .append(" (").append(exceptionName(exCode)).append(")");
            }
            summary.append(" · unit=").append(unitId).append(" · txn=").append(txnId);
            return summary.toString();
        }

        // --- Standard PDUs --------------------------------------------------
        // The data layout differs between request and response for the same
        // function code, so we branch on direction.
        final int pduOffset = MBAP_HEADER_LEN + 1; // first byte after FC
        boolean parsedWrite = false;

        switch (fc) {
            case 0x01: // Read Coils
            case 0x02: // Read Discrete Inputs
            case 0x03: // Read Holding Registers
            case 0x04: // Read Input Registers
                info.putDpiField("is_write", "false");
                if (isRequest && payload.length >= pduOffset + 4) {
                    int startAddr = u16(payload, pduOffset);
                    int qty = u16(payload, pduOffset + 2);
                    info.putDpiField("register_address", String.valueOf(startAddr));
                    info.putDpiField("quantity", String.valueOf(qty));
                    summary.append(" · addr=").append(startAddr).append(" × ").append(qty);
                } else if (!isRequest && payload.length >= pduOffset + 1) {
                    int byteCount = payload[pduOffset] & 0xFF;
                    info.putDpiField("byte_count", String.valueOf(byteCount));
                    summary.append(" · bytes=").append(byteCount);
                }
                break;

            case 0x05: // Write Single Coil
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                if (payload.length >= pduOffset + 4) {
                    int addr = u16(payload, pduOffset);
                    int val = u16(payload, pduOffset + 2);
                    String valStr = val == 0xFF00 ? "ON" : val == 0x0000 ? "OFF" : String.format("0x%04X", val);
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("value", valStr);
                    summary.append(" · coil=").append(addr).append(" ← ").append(valStr);
                }
                break;

            case 0x06: // Write Single Register
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                if (payload.length >= pduOffset + 4) {
                    int addr = u16(payload, pduOffset);
                    int val = u16(payload, pduOffset + 2);
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("value", String.valueOf(val));
                    summary.append(" · reg=").append(addr).append(" ← ").append(val);
                }
                break;

            case 0x07: // Read Exception Status
                info.putDpiField("is_write", "false");
                if (!isRequest && payload.length >= pduOffset + 1) {
                    int st = payload[pduOffset] & 0xFF;
                    info.putDpiField("exception_status", String.format("0x%02X", st));
                    summary.append(" · status=").append(String.format("0x%02X", st));
                }
                break;

            case 0x0F: // Write Multiple Coils
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                if (isRequest && payload.length >= pduOffset + 5) {
                    int addr = u16(payload, pduOffset);
                    int qty = u16(payload, pduOffset + 2);
                    int byteCount = payload[pduOffset + 4] & 0xFF;
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("quantity", String.valueOf(qty));
                    info.putDpiField("byte_count", String.valueOf(byteCount));
                    summary.append(" · coils=").append(addr).append(" × ").append(qty);
                } else if (!isRequest && payload.length >= pduOffset + 4) {
                    int addr = u16(payload, pduOffset);
                    int qty = u16(payload, pduOffset + 2);
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("quantity", String.valueOf(qty));
                    summary.append(" · coils=").append(addr).append(" × ").append(qty);
                }
                break;

            case 0x10: // Write Multiple Registers
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                if (isRequest && payload.length >= pduOffset + 5) {
                    int addr = u16(payload, pduOffset);
                    int qty = u16(payload, pduOffset + 2);
                    int byteCount = payload[pduOffset + 4] & 0xFF;
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("quantity", String.valueOf(qty));
                    info.putDpiField("byte_count", String.valueOf(byteCount));
                    // Capture up to the first 4 written register values so the
                    // UI can show what was written without dumping huge blobs.
                    StringBuilder vals = new StringBuilder();
                    int valOff = pduOffset + 5;
                    int valsToRead = Math.min(qty, 4);
                    for (int i = 0; i < valsToRead && valOff + 1 < payload.length; i++, valOff += 2) {
                        if (vals.length() > 0) vals.append(',');
                        vals.append(u16(payload, valOff));
                    }
                    if (vals.length() > 0) {
                        info.putDpiField("values", vals.toString() + (qty > valsToRead ? ",…" : ""));
                    }
                    summary.append(" · regs=").append(addr).append(" × ").append(qty);
                    if (vals.length() > 0) summary.append(" ← [").append(vals).append(qty > valsToRead ? ",…" : "").append(']');
                } else if (!isRequest && payload.length >= pduOffset + 4) {
                    int addr = u16(payload, pduOffset);
                    int qty = u16(payload, pduOffset + 2);
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("quantity", String.valueOf(qty));
                    summary.append(" · regs=").append(addr).append(" × ").append(qty);
                }
                break;

            case 0x16: // Mask Write Register
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                if (payload.length >= pduOffset + 6) {
                    int addr = u16(payload, pduOffset);
                    int andMask = u16(payload, pduOffset + 2);
                    int orMask = u16(payload, pduOffset + 4);
                    info.putDpiField("register_address", String.valueOf(addr));
                    info.putDpiField("and_mask", String.format("0x%04X", andMask));
                    info.putDpiField("or_mask", String.format("0x%04X", orMask));
                    summary.append(" · reg=").append(addr)
                           .append(" AND=").append(String.format("0x%04X", andMask))
                           .append(" OR=").append(String.format("0x%04X", orMask));
                }
                break;

            case 0x17: // Read/Write Multiple Registers
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                if (isRequest && payload.length >= pduOffset + 9) {
                    int readAddr = u16(payload, pduOffset);
                    int readQty = u16(payload, pduOffset + 2);
                    int writeAddr = u16(payload, pduOffset + 4);
                    int writeQty = u16(payload, pduOffset + 6);
                    info.putDpiField("read_address", String.valueOf(readAddr));
                    info.putDpiField("read_quantity", String.valueOf(readQty));
                    info.putDpiField("write_address", String.valueOf(writeAddr));
                    info.putDpiField("write_quantity", String.valueOf(writeQty));
                    summary.append(" · read=").append(readAddr).append(" × ").append(readQty)
                           .append(" / write=").append(writeAddr).append(" × ").append(writeQty);
                }
                break;

            case 0x2B: // Encapsulated Interface (Read Device Identification)
                info.putDpiField("is_write", "false");
                if (payload.length >= pduOffset + 1) {
                    int meiType = payload[pduOffset] & 0xFF;
                    info.putDpiField("mei_type", String.format("0x%02X", meiType));
                    if (meiType == 0x0E) summary.append(" · Read Device ID");
                }
                break;

            default:
                info.putDpiField("is_write", "unknown");
                break;
        }

        summary.append(" · unit=").append(unitId).append(" · txn=").append(txnId);

        if (parsedWrite) {
            // Convenient flag for downstream anomaly logic: "writes from
            // unexpected source" etc.
            info.putDpiField("pdu_kind", "write");
        } else {
            info.putDpiField("pdu_kind", fc <= 0x04 || fc == 0x07 ? "read" : "other");
        }

        return summary.toString();
    }

    // --- Helpers -----------------------------------------------------------

    private static boolean isClientToServer(int srcPort, int dstPort) {
        // Servers listen on 502 - traffic going TO 502 is a request.
        if (dstPort == MODBUS_TCP_PORT && srcPort != MODBUS_TCP_PORT) return true;
        if (srcPort == MODBUS_TCP_PORT && dstPort != MODBUS_TCP_PORT) return false;
        // Unclear (e.g. both or neither) - guess "response" so we parse
        // defensively (reads with no register assumptions).
        return false;
    }

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    public static String functionName(int fc) {
        switch (fc) {
            case 0x01: return "Read Coils";
            case 0x02: return "Read Discrete Inputs";
            case 0x03: return "Read Holding Registers";
            case 0x04: return "Read Input Registers";
            case 0x05: return "Write Single Coil";
            case 0x06: return "Write Single Register";
            case 0x07: return "Read Exception Status";
            case 0x08: return "Diagnostics";
            case 0x0B: return "Get Comm Event Counter";
            case 0x0C: return "Get Comm Event Log";
            case 0x0F: return "Write Multiple Coils";
            case 0x10: return "Write Multiple Registers";
            case 0x11: return "Report Server ID";
            case 0x14: return "Read File Record";
            case 0x15: return "Write File Record";
            case 0x16: return "Mask Write Register";
            case 0x17: return "Read/Write Multiple Registers";
            case 0x18: return "Read FIFO Queue";
            case 0x2B: return "Encapsulated Interface";
            default:   return String.format("Function 0x%02X", fc);
        }
    }

    public static String exceptionName(int code) {
        switch (code) {
            case 0x01: return "Illegal Function";
            case 0x02: return "Illegal Data Address";
            case 0x03: return "Illegal Data Value";
            case 0x04: return "Server Device Failure";
            case 0x05: return "Acknowledge";
            case 0x06: return "Server Device Busy";
            case 0x08: return "Memory Parity Error";
            case 0x0A: return "Gateway Path Unavailable";
            case 0x0B: return "Gateway Target Device Failed to Respond";
            default:   return String.format("Exception 0x%02X", code);
        }
    }
}

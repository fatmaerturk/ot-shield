package com.safetech.otshield.service.dpi;

import com.safetech.otshield.model.PacketInfo;

/**
 * Deep-packet-inspection dissector for Siemens S7Comm (ISO-on-TCP, port 102).
 *
 * <p>Wire encapsulation (big-endian):
 * <pre>
 *   TPKT  (4 bytes)    version | reserved | length-hi | length-lo
 *   COTP  (variable)   length | PDU-type | ...          (2 bytes minimum)
 *   S7COMM header      0x32 | ROSCTR | reserved(2) | PDURef(2) |
 *                      ParamLen(2) | DataLen(2) | [ErrorClass(1) |
 *                      ErrorCode(1) when ROSCTR=3]
 *   Parameters / Data
 * </pre>
 *
 * <p>ROSCTR values (Remote Operating Service Control):
 * <ul>
 *   <li>0x01 Job request</li>
 *   <li>0x02 Ack</li>
 *   <li>0x03 Ack-data (response)</li>
 *   <li>0x07 Userdata (SZL read, PLC control extended)</li>
 * </ul>
 *
 * <p>The dissector identifies common job types (Read Var, Write Var, PLC
 * Stop/Start/Copy Ram to ROM, Download/Upload block) and for Read/Write Var
 * parses the first item's area (DB/I/Q/M/T/C), DB number, address and length.
 */
public final class S7CommDissector {

    public static final int S7_PORT = 102;
    public static final byte S7_PROTOCOL_ID = 0x32;

    // ROSCTR
    public static final int ROSCTR_JOB = 0x01;
    public static final int ROSCTR_ACK = 0x02;
    public static final int ROSCTR_ACK_DATA = 0x03;
    public static final int ROSCTR_USERDATA = 0x07;

    private S7CommDissector() {
        // Utility class
    }

    /**
     * Dissect the TCP payload of an S7 connection. Returns a compact summary
     * string when the payload looks like valid S7Comm, otherwise null.
     */
    public static String dissect(byte[] payload, int srcPort, int dstPort, PacketInfo info) {
        if (payload == null || payload.length < 4 + 2 + 10 || info == null) {
            return null;
        }

        // --- TPKT -----------------------------------------------------------
        int tpktVersion = payload[0] & 0xFF;
        if (tpktVersion != 0x03) {
            return null; // Not TPKT - not S7
        }
        int tpktLen = ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF);
        if (tpktLen < 7 || tpktLen > payload.length) {
            // Length mismatch - may still be S7 but suspicious
            info.putDpiField("tpkt_length_mismatch", "true");
        }

        // --- COTP -----------------------------------------------------------
        int cotpLen = payload[4] & 0xFF;
        int cotpPduType = payload[5] & 0xFF;
        // S7 data only travels in COTP DT (0xF0). CR/CC handshake = 0xE0/0xD0.
        int s7Off = 4 + 1 + cotpLen; // 4 TPKT + 1 lenByte + cotpLen
        if (cotpPduType != 0xF0) {
            // Still emit a tiny summary for the handshake so the UI can show
            // "S7 setup (COTP CR)"
            info.putDpiField("cotp_pdu_type", String.format("0x%02X", cotpPduType));
            String phase = cotpPduType == 0xE0 ? "COTP Connect Request"
                         : cotpPduType == 0xD0 ? "COTP Connect Confirm"
                         : String.format("COTP 0x%02X", cotpPduType);
            return "S7 · " + phase;
        }

        if (s7Off + 10 > payload.length) {
            return null;
        }
        if ((payload[s7Off] & 0xFF) != (S7_PROTOCOL_ID & 0xFF)) {
            return null; // Not S7 protocol ID
        }

        // --- S7 header ------------------------------------------------------
        int rosctr = payload[s7Off + 1] & 0xFF;
        int pduRef = ((payload[s7Off + 4] & 0xFF) << 8) | (payload[s7Off + 5] & 0xFF);
        int paramLen = ((payload[s7Off + 6] & 0xFF) << 8) | (payload[s7Off + 7] & 0xFF);
        int dataLen = ((payload[s7Off + 8] & 0xFF) << 8) | (payload[s7Off + 9] & 0xFF);

        int headerLen = (rosctr == ROSCTR_ACK_DATA) ? 12 : 10;
        int paramOff = s7Off + headerLen;

        info.putDpiField("rosctr", String.format("0x%02X", rosctr));
        info.putDpiField("rosctr_name", rosctrName(rosctr));
        info.putDpiField("pdu_ref", String.valueOf(pduRef));
        info.putDpiField("param_length", String.valueOf(paramLen));
        info.putDpiField("data_length", String.valueOf(dataLen));

        // Error class/code for Ack-Data
        if (rosctr == ROSCTR_ACK_DATA && s7Off + 12 <= payload.length) {
            int errClass = payload[s7Off + 10] & 0xFF;
            int errCode = payload[s7Off + 11] & 0xFF;
            info.putDpiField("error_class", String.format("0x%02X", errClass));
            info.putDpiField("error_code", String.format("0x%02X", errCode));
            if (errClass != 0 || errCode != 0) {
                info.putDpiField("has_error", "true");
            }
        }

        // --- Parameter block: first byte is function code -------------------
        if (paramLen < 1 || paramOff + paramLen > payload.length) {
            return "S7 · " + rosctrName(rosctr) + " · ref=" + pduRef;
        }
        int fc = payload[paramOff] & 0xFF;

        info.putDpiField("function_code", String.format("0x%02X", fc));
        info.putDpiField("function_name", s7FunctionName(fc));

        StringBuilder summary = new StringBuilder();
        summary.append("S7 · ").append(rosctrName(rosctr)).append(" · ").append(s7FunctionName(fc));

        boolean parsedWrite = false;

        switch (fc) {
            case 0x04: // Read Variable
            case 0x05: // Write Variable
                parsedWrite = (fc == 0x05);
                info.putDpiField("is_write", String.valueOf(parsedWrite));
                if (rosctr == ROSCTR_JOB && paramLen >= 2) {
                    int itemCount = payload[paramOff + 1] & 0xFF;
                    info.putDpiField("item_count", String.valueOf(itemCount));
                    // Parse the FIRST item only - common case; adequate for UI.
                    // Item structure (12 bytes for "ANY" addressing):
                    //   0x12 VarSpec | length (0x0A) | syntaxId (0x10)
                    //   transportSize | accessLength(2) | dbNumber(2)
                    //   area(1) | address(3, bits at LSB)
                    int itemOff = paramOff + 2;
                    if (itemOff + 12 <= payload.length && (payload[itemOff] & 0xFF) == 0x12) {
                        int transportSize = payload[itemOff + 3] & 0xFF;
                        int accessLength = ((payload[itemOff + 4] & 0xFF) << 8) | (payload[itemOff + 5] & 0xFF);
                        int dbNumber = ((payload[itemOff + 6] & 0xFF) << 8) | (payload[itemOff + 7] & 0xFF);
                        int area = payload[itemOff + 8] & 0xFF;
                        int addrRaw = ((payload[itemOff + 9] & 0xFF) << 16)
                                    | ((payload[itemOff + 10] & 0xFF) << 8)
                                    | (payload[itemOff + 11] & 0xFF);
                        // Address is bit-addressed: shift right 3 → byte, low 3 bits → bit
                        int byteAddr = addrRaw >> 3;
                        int bitAddr = addrRaw & 0x07;
                        String areaName = s7AreaName(area);

                        info.putDpiField("area", areaName);
                        info.putDpiField("db_number", String.valueOf(dbNumber));
                        info.putDpiField("address", String.valueOf(byteAddr));
                        info.putDpiField("bit_offset", String.valueOf(bitAddr));
                        info.putDpiField("length", String.valueOf(accessLength));
                        info.putDpiField("transport_size", s7TransportSizeName(transportSize));

                        summary.append(" · ");
                        if ("DB".equals(areaName) && dbNumber > 0) {
                            summary.append("DB").append(dbNumber).append('.');
                        } else {
                            summary.append(areaName);
                        }
                        summary.append("DBX").append(byteAddr);
                        if (bitAddr > 0) summary.append('.').append(bitAddr);
                        summary.append(" × ").append(accessLength);

                        // For Write Var on Job, try to pull the first value
                        if (fc == 0x05 && rosctr == ROSCTR_JOB) {
                            // Data section begins at paramOff + paramLen
                            int dataOff = paramOff + paramLen;
                            if (dataOff + 4 <= payload.length) {
                                // Data item: returnCode(1) | transportSize(1) | length(2) | data
                                int dataLen1 = ((payload[dataOff + 2] & 0xFF) << 8) | (payload[dataOff + 3] & 0xFF);
                                // Length here is either in bits or bytes depending on ts
                                int bytes = (dataLen1 + 7) / 8; // treat as bits defensively
                                int readBytes = Math.min(4, Math.min(bytes, payload.length - dataOff - 4));
                                if (readBytes > 0) {
                                    StringBuilder hex = new StringBuilder();
                                    for (int i = 0; i < readBytes; i++) {
                                        if (hex.length() > 0) hex.append(' ');
                                        hex.append(String.format("%02X", payload[dataOff + 4 + i]));
                                    }
                                    info.putDpiField("value_hex", hex.toString());
                                    summary.append(" ← ").append(hex);
                                }
                            }
                        }
                    }
                }
                break;

            case 0x1A: // Request download
            case 0x1B: // Download block
            case 0x1C: // Download ended
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                info.putDpiField("is_block_transfer", "true");
                info.putDpiField("direction", "download");
                break;

            case 0x1D: // Start upload
            case 0x1E: // Upload
            case 0x1F: // End upload
                info.putDpiField("is_write", "false");
                info.putDpiField("is_block_transfer", "true");
                info.putDpiField("direction", "upload");
                break;

            case 0x28: // PLC Control (Insert/Delete/Run etc.)
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                info.putDpiField("is_plc_control", "true");
                info.putDpiField("plc_action", "insert/delete block");
                break;

            case 0x29: // PLC Stop
                parsedWrite = true;
                info.putDpiField("is_write", "true");
                info.putDpiField("is_plc_control", "true");
                info.putDpiField("plc_action", "STOP");
                summary.append(" · ⚠ STOP");
                break;

            case 0xF0: // Setup Communication
                info.putDpiField("is_write", "false");
                info.putDpiField("is_setup", "true");
                break;

            default:
                info.putDpiField("is_write", "unknown");
                break;
        }

        summary.append(" · ref=").append(pduRef);

        if (parsedWrite) {
            info.putDpiField("pdu_kind", "write");
        } else if (fc == 0x04 || fc == 0x1D || fc == 0x1E || fc == 0x1F) {
            info.putDpiField("pdu_kind", "read");
        } else {
            info.putDpiField("pdu_kind", "other");
        }

        return summary.toString();
    }

    // --- Name tables -------------------------------------------------------

    public static String rosctrName(int r) {
        switch (r) {
            case ROSCTR_JOB:      return "Job";
            case ROSCTR_ACK:      return "Ack";
            case ROSCTR_ACK_DATA: return "Ack-Data";
            case ROSCTR_USERDATA: return "Userdata";
            default:              return String.format("ROSCTR 0x%02X", r);
        }
    }

    public static String s7FunctionName(int fc) {
        switch (fc) {
            case 0x00: return "CPU Services";
            case 0x04: return "Read Var";
            case 0x05: return "Write Var";
            case 0x1A: return "Request Download";
            case 0x1B: return "Download Block";
            case 0x1C: return "Download Ended";
            case 0x1D: return "Start Upload";
            case 0x1E: return "Upload";
            case 0x1F: return "End Upload";
            case 0x28: return "PLC Control";
            case 0x29: return "PLC Stop";
            case 0xF0: return "Setup Communication";
            default:   return String.format("Function 0x%02X", fc);
        }
    }

    public static String s7AreaName(int area) {
        switch (area) {
            case 0x03: return "SysInfo";
            case 0x05: return "SysFlags";
            case 0x06: return "AnaIn";
            case 0x07: return "AnaOut";
            case 0x1C: return "C";   // Counters
            case 0x1D: return "T";   // Timers
            case 0x80: return "P";   // Peripheral I/O
            case 0x81: return "I";   // Process Inputs
            case 0x82: return "Q";   // Process Outputs
            case 0x83: return "M";   // Flags / Merker
            case 0x84: return "DB";  // Data blocks
            case 0x85: return "DI";  // Instance DB
            case 0x86: return "L";   // Local data
            case 0x87: return "V";   // Previous local data
            default:   return String.format("Area 0x%02X", area);
        }
    }

    public static String s7TransportSizeName(int ts) {
        switch (ts) {
            case 0x01: return "BIT";
            case 0x02: return "BYTE";
            case 0x03: return "CHAR";
            case 0x04: return "WORD";
            case 0x05: return "INT";
            case 0x06: return "DWORD";
            case 0x07: return "DINT";
            case 0x08: return "REAL";
            case 0x09: return "DATE";
            case 0x0A: return "TOD";
            case 0x0B: return "TIME";
            case 0x0C: return "S5TIME";
            default:   return String.format("TS 0x%02X", ts);
        }
    }
}

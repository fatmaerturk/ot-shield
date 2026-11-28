package com.safetech.otshield.service.dpi;

import com.safetech.otshield.model.PacketInfo;

/**
 * Deep-packet-inspection dissector for IEC 60870-5-104 (IANA port 2404), the
 * TCP telecontrol protocol used on power-grid SCADA networks.
 *
 * <p>APCI (6 bytes): {@code 0x68}, length, 4 control octets. Three frame formats:
 * <ul>
 *   <li><b>I</b> (information) - carries an ASDU; LSB of control octet 1 is 0.</li>
 *   <li><b>S</b> (supervisory) - pure ack; control octet 1 low bits {@code 01}.</li>
 *   <li><b>U</b> (unnumbered) - STARTDT / STOPDT / TESTFR; low bits {@code 11}.</li>
 * </ul>
 *
 * <p>ASDU: type id, variable structure qualifier (SQ + object count), cause of
 * transmission (2 octets incl. originator), common address (2 octets LE), then
 * information objects (3-octet IOA + elements).
 *
 * <p>Populates {@link PacketInfo#getDpiFields()} and returns a one-line summary.
 * Safe on any byte array; returns {@code null} when the buffer is not IEC-104,
 * so a generic TCP packet on 2404 never produces a bogus event.
 */
public final class IEC104Dissector {

    public static final int IEC104_PORT = 2404;

    private IEC104Dissector() {
        // Utility class
    }

    public static String dissect(byte[] p, int srcPort, int dstPort, PacketInfo info) {
        if (p == null || info == null || p.length < 6) return null;
        if ((p[0] & 0xFF) != 0x68) return null; // not APCI framing -> not IEC-104

        int apduLen = p[1] & 0xFF; // octets after the length octet (4 control + ASDU)
        int c0 = p[2] & 0xFF, c1 = p[3] & 0xFF, c2 = p[4] & 0xFF, c3 = p[5] & 0xFF;

        info.putDpiField("apdu_length", String.valueOf(apduLen));
        boolean truncated = p.length < apduLen + 2;
        info.putDpiField("apdu_length_mismatch", String.valueOf(truncated));

        // --- U-format (unnumbered control) ---------------------------------
        if ((c0 & 0x03) == 0x03) {
            String name = uName(c0);
            info.putDpiField("apci_type", "U");
            info.putDpiField("u_function", name);
            info.putDpiField("function_name", name);
            info.putDpiField("pdu_kind", "control");
            String s = "IEC104 U-format: " + name;
            info.setPayloadInfo(s);
            return s;
        }

        // --- S-format (supervisory ack) ------------------------------------
        if ((c0 & 0x03) == 0x01) {
            int nr = ((c3 << 8) | c2) >> 1;
            info.putDpiField("apci_type", "S");
            info.putDpiField("recv_seq", String.valueOf(nr));
            // Intentionally no function_name/pdu_kind -> pure ack is not persisted
            // as a DPI event (keeps the inspector focused on real PDUs).
            return "IEC104 S-format (ack) NR=" + nr;
        }

        // --- I-format (information transfer) -------------------------------
        int ns = ((c1 << 8) | c0) >> 1;
        int nr = ((c3 << 8) | c2) >> 1;
        info.putDpiField("apci_type", "I");
        info.putDpiField("send_seq", String.valueOf(ns));
        info.putDpiField("recv_seq", String.valueOf(nr));

        if (p.length < 12) { // APCI present but ASDU header incomplete
            info.putDpiField("function_name", "I-format (no ASDU)");
            info.putDpiField("pdu_kind", "monitor");
            String s = "IEC104 I-format NS=" + ns + " NR=" + nr;
            info.setPayloadInfo(s);
            return s;
        }

        int typeId = p[6] & 0xFF;
        int vsq = p[7] & 0xFF;
        int numObj = vsq & 0x7F;
        boolean sq = (vsq & 0x80) != 0;
        int cot = p[8] & 0x3F;
        boolean negative = (p[8] & 0x40) != 0;
        boolean test = (p[8] & 0x80) != 0;
        int orig = p[9] & 0xFF;
        int ca = (p[10] & 0xFF) | ((p[11] & 0xFF) << 8);

        String typeName = typeName(typeId);
        info.putDpiField("type_id", String.valueOf(typeId));
        info.putDpiField("function_code", String.valueOf(typeId));
        info.putDpiField("function_name", typeName);
        info.putDpiField("cot", String.valueOf(cot));
        info.putDpiField("cot_name", cotName(cot));
        info.putDpiField("originator", String.valueOf(orig));
        info.putDpiField("common_address", String.valueOf(ca));
        info.putDpiField("num_objects", String.valueOf(numObj));
        info.putDpiField("sq", String.valueOf(sq));
        if (test) info.putDpiField("test", "true");
        if (negative) info.putDpiField("negative", "true");

        String ioaStr = "-";
        if (p.length >= 15) {
            int ioa = (p[12] & 0xFF) | ((p[13] & 0xFF) << 8) | ((p[14] & 0xFF) << 16);
            ioaStr = String.valueOf(ioa);
            info.putDpiField("ioa", ioaStr);
            try {
                if ((typeId == 13 || typeId == 36) && p.length >= 19) { // short float value
                    int bits = (p[15] & 0xFF) | ((p[16] & 0xFF) << 8) | ((p[17] & 0xFF) << 16) | ((p[18] & 0xFF) << 24);
                    info.putDpiField("value", String.valueOf(Float.intBitsToFloat(bits)));
                } else if (typeId == 1 && p.length >= 16) { // single point SIQ
                    info.putDpiField("value", ((p[15] & 0x01) != 0) ? "ON" : "OFF");
                } else if (typeId == 45 && p.length >= 16) { // single command SCO
                    info.putDpiField("value", ((p[15] & 0x01) != 0) ? "ON" : "OFF");
                }
            } catch (Exception ignore) {
                // best-effort value extraction only
            }
        }

        boolean isCmd = (typeId >= 45 && typeId <= 51) || (typeId >= 58 && typeId <= 64);
        boolean isSys = typeId >= 100; // interrogation / clock sync / reset / test
        if (isCmd) {
            info.putDpiField("is_write", "true");
            info.putDpiField("is_command", "true");
            info.putDpiField("pdu_kind", "write");
        } else if (isSys) {
            info.putDpiField("is_command", "true");
            info.putDpiField("pdu_kind", "control");
        } else {
            info.putDpiField("pdu_kind", "monitor");
        }

        String s = "IEC104 " + typeName + " (" + cotName(cot) + "), CA=" + ca
                + ", IOA=" + ioaStr + ", objs=" + numObj;
        info.setPayloadInfo(s);
        return s;
    }

    private static String uName(int c0) {
        switch (c0) {
            case 0x07: return "STARTDT act";
            case 0x0B: return "STARTDT con";
            case 0x13: return "STOPDT act";
            case 0x23: return "STOPDT con";
            case 0x43: return "TESTFR act";
            case 0x83: return "TESTFR con";
            default:   return "U-frame 0x" + Integer.toHexString(c0);
        }
    }

    private static String typeName(int t) {
        switch (t) {
            case 1:   return "M_SP_NA_1 Single point";
            case 3:   return "M_DP_NA_1 Double point";
            case 5:   return "M_ST_NA_1 Step position";
            case 7:   return "M_BO_NA_1 Bitstring";
            case 9:   return "M_ME_NA_1 Measured normalized";
            case 11:  return "M_ME_NB_1 Measured scaled";
            case 13:  return "M_ME_NC_1 Measured short float";
            case 15:  return "M_IT_NA_1 Integrated totals";
            case 30:  return "M_SP_TB_1 Single point w/ time";
            case 31:  return "M_DP_TB_1 Double point w/ time";
            case 36:  return "M_ME_TF_1 Measured short float w/ time";
            case 45:  return "C_SC_NA_1 Single command";
            case 46:  return "C_DC_NA_1 Double command";
            case 47:  return "C_RC_NA_1 Regulating step command";
            case 48:  return "C_SE_NA_1 Set point normalized";
            case 49:  return "C_SE_NB_1 Set point scaled";
            case 50:  return "C_SE_NC_1 Set point short float";
            case 51:  return "C_BO_NA_1 Bitstring command";
            case 70:  return "M_EI_NA_1 End of initialization";
            case 100: return "C_IC_NA_1 Interrogation command";
            case 101: return "C_CI_NA_1 Counter interrogation";
            case 102: return "C_RD_NA_1 Read command";
            case 103: return "C_CS_NA_1 Clock synchronization";
            case 105: return "C_RP_NA_1 Reset process command";
            case 107: return "C_TS_TA_1 Test command w/ time";
            default:  return "Type " + t;
        }
    }

    private static String cotName(int c) {
        switch (c) {
            case 1:  return "periodic";
            case 2:  return "background scan";
            case 3:  return "spontaneous";
            case 4:  return "initialized";
            case 5:  return "request";
            case 6:  return "activation";
            case 7:  return "activation confirm";
            case 8:  return "deactivation";
            case 9:  return "deactivation confirm";
            case 10: return "activation termination";
            case 20: return "interrogated (GI)";
            case 37: return "counter interrogated";
            case 44: return "unknown type id";
            case 45: return "unknown cause";
            case 46: return "unknown common address";
            case 47: return "unknown IOA";
            default:
                if (c >= 21 && c <= 36) return "interrogated group " + (c - 20);
                return "cot " + c;
        }
    }
}

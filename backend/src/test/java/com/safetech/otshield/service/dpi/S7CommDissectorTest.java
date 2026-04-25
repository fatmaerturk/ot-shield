package com.safetech.otshield.service.dpi;

import com.safetech.otshield.model.PacketInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * S7Comm hex payloads are built from the published protocol reference:
 * TPKT + COTP-DT + S7 header + Parameters.
 */
class S7CommDissectorTest {

    private static byte[] hex(String s) {
        String clean = s.replace(" ", "").replace("\n", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Test
    void readVarRequest_parsesDbAreaAndAddress() {
        // TPKT: 03 00 00 1F (version, reserved, length=31)
        // COTP: 02 F0 80 (len=2, PDU type=DT, tpdu-nr=0x80)
        // S7  : 32 01 00 00 00 01 00 0E 00 00 (ROSCTR=Job, PDURef=1, ParLen=14, DatLen=0)
        // Param: 04 01  (ReadVar, 1 item)
        //        12 0A 10 02 00 01 00 01 84 00 00 00 (Item: ANY, DB1, area=DB, addr=0)
        byte[] payload = hex(
            "03 00 00 1F" +
            "02 F0 80" +
            "32 01 00 00 00 01 00 0E 00 00" +
            "04 01" +
            "12 0A 10 02 00 01 00 01 84 00 00 00"
        );
        PacketInfo info = new PacketInfo();

        String summary = S7CommDissector.dissect(payload, 49152, 102, info);

        assertNotNull(summary);
        assertTrue(summary.contains("Read Var"), summary);
        assertEquals("Job", info.getDpiFields().get("rosctr_name"));
        assertEquals("0x04", info.getDpiFields().get("function_code"));
        assertEquals("Read Var", info.getDpiFields().get("function_name"));
        assertEquals("DB", info.getDpiFields().get("area"));
        assertEquals("1", info.getDpiFields().get("db_number"));
        assertEquals("0", info.getDpiFields().get("address"));
        assertEquals("1", info.getDpiFields().get("length"));
        assertEquals("BYTE", info.getDpiFields().get("transport_size"));
        assertEquals("false", info.getDpiFields().get("is_write"));
        assertEquals("read", info.getDpiFields().get("pdu_kind"));
    }

    @Test
    void writeVarRequest_markedAsWrite() {
        // Same layout but FC=0x05 (Write Var), plus a 4-byte data section
        // Data: 00 04 00 08 AA BB CC DD  (returnCode=0, ts=BYTE, len=8 bits = 1 byte... we send 4)
        byte[] payload = hex(
            "03 00 00 27" +
            "02 F0 80" +
            "32 01 00 00 00 02 00 0E 00 08" +
            "05 01" +
            "12 0A 10 02 00 04 00 01 84 00 00 00" +
            "00 04 00 20 AA BB CC DD"
        );
        PacketInfo info = new PacketInfo();

        String summary = S7CommDissector.dissect(payload, 49152, 102, info);

        assertNotNull(summary);
        assertTrue(summary.contains("Write Var"), summary);
        assertEquals("Write Var", info.getDpiFields().get("function_name"));
        assertEquals("true", info.getDpiFields().get("is_write"));
        assertEquals("DB", info.getDpiFields().get("area"));
        assertEquals("1", info.getDpiFields().get("db_number"));
        assertEquals("4", info.getDpiFields().get("length"));
        assertEquals("write", info.getDpiFields().get("pdu_kind"));
        // value_hex should contain at least the start of the hex payload
        String valHex = info.getDpiFields().get("value_hex");
        assertNotNull(valHex);
        assertTrue(valHex.startsWith("AA"), valHex);
    }

    @Test
    void plcStop_flaggedAsControlAction() {
        // Minimal Job with FC=0x29 (PLC Stop), param len 1
        byte[] payload = hex(
            "03 00 00 12" +
            "02 F0 80" +
            "32 01 00 00 00 03 00 01 00 00" +
            "29"
        );
        PacketInfo info = new PacketInfo();

        String summary = S7CommDissector.dissect(payload, 49152, 102, info);

        assertNotNull(summary);
        assertTrue(summary.contains("STOP"), summary);
        assertEquals("PLC Stop", info.getDpiFields().get("function_name"));
        assertEquals("true", info.getDpiFields().get("is_plc_control"));
        assertEquals("STOP", info.getDpiFields().get("plc_action"));
        assertEquals("write", info.getDpiFields().get("pdu_kind"));
    }

    @Test
    void cotpConnectRequest_returnsHandshakeSummary() {
        // TPKT + COTP Connect Request (0xE0) → short summary, no S7 header
        byte[] payload = hex(
            "03 00 00 16" +
            "11 E0 00 00 00 01 00 C0 01 0A C1 02 01 00 C2 02 01 02"
        );
        PacketInfo info = new PacketInfo();

        String summary = S7CommDissector.dissect(payload, 49152, 102, info);

        assertNotNull(summary);
        assertTrue(summary.contains("COTP Connect Request"), summary);
        assertEquals("0xE0", info.getDpiFields().get("cotp_pdu_type"));
    }

    @Test
    void nonTpktPayload_returnsNull() {
        // Doesn't start with TPKT version 0x03
        byte[] payload = hex("00 00 00 00 00 00");
        PacketInfo info = new PacketInfo();
        assertNull(S7CommDissector.dissect(payload, 49152, 102, info));
    }

    @Test
    void shortPayload_returnsNull() {
        PacketInfo info = new PacketInfo();
        assertNull(S7CommDissector.dissect(new byte[]{0x03, 0x00, 0x00, 0x05}, 49152, 102, info));
    }

    @Test
    void nullInputs_returnNullSafely() {
        assertNull(S7CommDissector.dissect(null, 0, 0, new PacketInfo()));
        assertNull(S7CommDissector.dissect(new byte[]{0x03, 0x00}, 0, 0, null));
    }
}

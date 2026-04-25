package com.safetech.otshield.service.dpi;

import com.safetech.otshield.model.PacketInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Hex payloads in these tests are taken from the Modbus TCP specification
 * and from Wireshark captures of real PLC traffic.
 */
class ModbusDissectorTest {

    // Helper - convert a hex string ("00 01 02") into byte[]
    private static byte[] hex(String s) {
        String clean = s.replace(" ", "").replace("\n", "");
        int len = clean.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Test
    void readHoldingRegistersRequest_parsesAddressAndQuantity() {
        // TxnId=0x0001 Proto=0x0000 Len=0x0006 UnitId=0x11
        // FC=0x03 Addr=0x006B Qty=0x0003
        byte[] payload = hex("00 01 00 00 00 06 11 03 00 6B 00 03");
        PacketInfo info = new PacketInfo();

        String summary = ModbusDissector.dissect(payload, 49152, 502, info);

        assertNotNull(summary);
        assertTrue(summary.contains("Read Holding Registers"));
        assertEquals("0x03", info.getDpiFields().get("function_code"));
        assertEquals("Read Holding Registers", info.getDpiFields().get("function_name"));
        assertEquals("17", info.getDpiFields().get("unit_id"));
        assertEquals("1", info.getDpiFields().get("transaction_id"));
        assertEquals("107", info.getDpiFields().get("register_address"));
        assertEquals("3", info.getDpiFields().get("quantity"));
        assertEquals("false", info.getDpiFields().get("is_write"));
        assertEquals("false", info.getDpiFields().get("is_exception"));
        assertEquals("request", info.getDpiFields().get("direction"));
        assertEquals("read", info.getDpiFields().get("pdu_kind"));
    }

    @Test
    void readHoldingRegistersResponse_parsesByteCount() {
        // Response: FC=0x03 ByteCount=0x06 Regs=0x022B 0x0000 0x0064
        byte[] payload = hex("00 01 00 00 00 09 11 03 06 02 2B 00 00 00 64");
        PacketInfo info = new PacketInfo();

        String summary = ModbusDissector.dissect(payload, 502, 49152, info);

        assertNotNull(summary);
        assertEquals("response", info.getDpiFields().get("direction"));
        assertEquals("6", info.getDpiFields().get("byte_count"));
        assertEquals("Read Holding Registers", info.getDpiFields().get("function_name"));
    }

    @Test
    void writeSingleRegister_parsesAddressAndValue() {
        // FC=0x06 Addr=0x0001 Value=0x0003
        byte[] payload = hex("00 01 00 00 00 06 11 06 00 01 00 03");
        PacketInfo info = new PacketInfo();

        String summary = ModbusDissector.dissect(payload, 49152, 502, info);

        assertNotNull(summary);
        assertTrue(summary.contains("Write Single Register"));
        assertTrue(summary.contains("reg=1"));
        assertTrue(summary.contains("← 3"));
        assertEquals("true", info.getDpiFields().get("is_write"));
        assertEquals("1", info.getDpiFields().get("register_address"));
        assertEquals("3", info.getDpiFields().get("value"));
        assertEquals("write", info.getDpiFields().get("pdu_kind"));
    }

    @Test
    void writeMultipleRegisters_capturesFirstFourValues() {
        // FC=0x10 Addr=0x0001 Qty=0x0002 ByteCount=0x04 Values=0x000A 0x0102
        byte[] payload = hex("00 01 00 00 00 0B 11 10 00 01 00 02 04 00 0A 01 02");
        PacketInfo info = new PacketInfo();

        String summary = ModbusDissector.dissect(payload, 49152, 502, info);

        assertNotNull(summary);
        assertTrue(summary.contains("Write Multiple Registers"));
        assertEquals("1", info.getDpiFields().get("register_address"));
        assertEquals("2", info.getDpiFields().get("quantity"));
        assertEquals("4", info.getDpiFields().get("byte_count"));
        assertEquals("10,258", info.getDpiFields().get("values"));
        assertEquals("true", info.getDpiFields().get("is_write"));
    }

    @Test
    void writeSingleCoil_mapsFF00ToOn() {
        // FC=0x05 Addr=0x00AC Value=0xFF00 (ON)
        byte[] payload = hex("00 01 00 00 00 06 11 05 00 AC FF 00");
        PacketInfo info = new PacketInfo();

        String summary = ModbusDissector.dissect(payload, 49152, 502, info);

        assertNotNull(summary);
        assertTrue(summary.contains("Write Single Coil"));
        assertEquals("172", info.getDpiFields().get("register_address"));
        assertEquals("ON", info.getDpiFields().get("value"));
    }

    @Test
    void exceptionResponse_parsesExceptionCode() {
        // FC=0x83 (exception bit set on Read Holding Registers) Ex=0x02 Illegal Data Address
        byte[] payload = hex("00 01 00 00 00 03 11 83 02");
        PacketInfo info = new PacketInfo();

        String summary = ModbusDissector.dissect(payload, 502, 49152, info);

        assertNotNull(summary);
        assertTrue(summary.contains("EXCEPTION"));
        assertTrue(summary.contains("Illegal Data Address"));
        assertEquals("true", info.getDpiFields().get("is_exception"));
        assertEquals("0x02", info.getDpiFields().get("exception_code"));
        assertEquals("Illegal Data Address", info.getDpiFields().get("exception_name"));
        // function_code is stripped of the exception bit
        assertEquals("0x03", info.getDpiFields().get("function_code"));
    }

    @Test
    void tooShortPayload_returnsNull() {
        PacketInfo info = new PacketInfo();
        assertNull(ModbusDissector.dissect(new byte[0], 49152, 502, info));
        assertNull(ModbusDissector.dissect(hex("00 01 00 00"), 49152, 502, info));
    }

    @Test
    void wrongProtocolId_returnsNull() {
        // protocol_id = 0x0001 instead of 0x0000 → not Modbus
        byte[] payload = hex("00 01 00 01 00 06 11 03 00 6B 00 03");
        PacketInfo info = new PacketInfo();
        assertNull(ModbusDissector.dissect(payload, 49152, 502, info));
    }

    @Test
    void nullInputs_returnNullSafely() {
        assertNull(ModbusDissector.dissect(null, 0, 0, new PacketInfo()));
        assertNull(ModbusDissector.dissect(new byte[]{1, 2, 3}, 0, 0, null));
    }
}

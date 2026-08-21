package com.safetech.otshield.dto.decoy;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Blueprint for a decoy digital twin: everything a decoy needs to impersonate a
 * discovered real asset - its identity (what a MODBUS Read Device Identification
 * would return) and the behaviour observed on the wire (which function codes it
 * actually speaks). This is pure data with NO listener; it is what the twin
 * emulator serves, what "Place" reasons about, and what "Attribute" maps back to.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TwinSpec {

    private String assetId;
    private String assetName;
    private String realIp;       // the real device this twin clones
    private String protocol;     // e.g. MODBUS

    private int unitId;

    // Identity served in a MODBUS Read Device Identification (FC43) response.
    private String vendor;       // object 0x00 VendorName
    private String productCode;  // object 0x01 ProductCode
    private String modelName;    // object 0x05 ModelName

    // Where the emulator listens. ALWAYS loopback - never exposed to a network.
    private String listenHost;   // "127.0.0.1"
    private Integer listenPort;  // null until the emulator is started

    // Behaviour observed from real traffic (for realism + display).
    private List<String> observedFunctions;
    private long observedEvents;

    private boolean running;     // is a localhost emulator currently serving this twin
}

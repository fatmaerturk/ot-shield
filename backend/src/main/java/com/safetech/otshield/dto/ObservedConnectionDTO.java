package com.safetech.otshield.dto;

import lombok.Builder;
import lombok.Data;

/**
 * A unique src→dst connection observed in the DPI stream, together with its
 * protocol and the number of PDUs exchanged. Drives the Network Topology
 * "observed connections" edges so the graph renders REAL pcap-derived traffic
 * instead of the hardcoded demo scenario.
 */
@Data
@Builder
public class ObservedConnectionDTO {
    /** Source IP of the connection. Never null. */
    private String sourceIp;
    /** Destination IP of the connection. Never null. */
    private String destinationIp;
    /** Protocol label from the dissector: MODBUS / S7COMM / IEC104 / … */
    private String protocol;
    /** Number of DPI events (PDUs) observed for this pair within the window. */
    private long count;
}

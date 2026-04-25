package com.safetech.otshield.dto;

import com.safetech.otshield.model.DpiEvent;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Flat, UI-friendly projection of {@link DpiEvent}. We deliberately drop
 * {@code dpiFieldsJson} from the list endpoint to keep payload sizes small;
 * it stays available from the single-event detail endpoint.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DpiEventDTO {

    private String id;
    private LocalDateTime eventTime;
    private String sourceIp;
    private String destinationIp;
    private Integer sourcePort;
    private Integer destinationPort;
    private String protocol;
    private String functionCode;
    private String functionName;
    private String pduKind;
    private Boolean isWrite;
    private Boolean isException;
    private String registerAddress;
    private String area;
    private String value;
    private String summary;
    /** Only populated by the detail endpoint - list endpoint leaves this null. */
    private String dpiFieldsJson;
    private String pcapSessionId;

    public static DpiEventDTO fromEntity(DpiEvent e, boolean includeFieldsJson) {
        if (e == null) return null;
        return DpiEventDTO.builder()
                .id(e.getId())
                .eventTime(e.getEventTime())
                .sourceIp(e.getSourceIp())
                .destinationIp(e.getDestinationIp())
                .sourcePort(e.getSourcePort())
                .destinationPort(e.getDestinationPort())
                .protocol(e.getProtocol())
                .functionCode(e.getFunctionCode())
                .functionName(e.getFunctionName())
                .pduKind(e.getPduKind())
                .isWrite(e.getIsWrite())
                .isException(e.getIsException())
                .registerAddress(e.getRegisterAddress())
                .area(e.getArea())
                .value(e.getValue())
                .summary(e.getSummary())
                .dpiFieldsJson(includeFieldsJson ? e.getDpiFieldsJson() : null)
                .pcapSessionId(e.getPcapSessionId())
                .build();
    }
}

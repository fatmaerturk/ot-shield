package com.safetech.otshield.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Result row for function-code aggregation endpoints. Serialises as
 * <code>{protocol:"MODBUS", functionCode:"0x06", functionName:"Write Single
 * Register", count:123}</code>.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FunctionCodeStatDTO {
    private String protocol;
    private String functionCode;
    private String functionName;
    private long count;
}

package com.safetech.otshield.dto.attacker;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A real asset this attacker was seen targeting (resolved from the destination IP). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TargetedAssetDTO {
    private String ip;
    private String name;
    private String purdueLevel;
    private String protocol;
}

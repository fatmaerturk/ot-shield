package com.safetech.otshield.dto.decoy;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * One self-healing adaptation the platform performed in response to a breach:
 * the trigger, the attacker, and the concrete actions it took (expand decoys /
 * block / rotate honeytoken). Rendered in the Decoy page "Adaptive Response"
 * feed to make the closed deception loop visible.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdaptationEventDTO {
    private String id;
    private Instant ts;
    private String trigger;      // TWIN_WRITE | HONEYTOKEN_TRIP | MANUAL
    private String sourceIp;
    private String assetName;
    private String protocol;
    private String summary;      // one-line human summary of the breach
    private List<Action> actions;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Action {
        private String type;     // EXPAND_DECOY | BLOCK_ATTACKER | ROTATE_HONEYTOKEN
        private String detail;
        private boolean success;
    }
}

package com.safetech.otshield.service.decoy;

/**
 * Published whenever a real breach signal is observed on the deception fabric
 * (an attacker writes to a decoy twin, or a honeytoken is tripped). Decoupled
 * as a Spring application event so the trigger sites (ModbusTwinEmulator,
 * HoneytokenService) do not depend on the adaptation orchestrator - avoiding a
 * bean dependency cycle. {@link DeceptionAdaptationService} listens for it.
 */
public class BreachDetectedEvent {

    /** TWIN_WRITE | HONEYTOKEN_TRIP */
    private final String trigger;
    private final String sourceIp;
    private final String assetId;
    private final String assetName;
    private final String protocol;
    private final String detail;

    public BreachDetectedEvent(String trigger, String sourceIp, String assetId,
                               String assetName, String protocol, String detail) {
        this.trigger = trigger;
        this.sourceIp = sourceIp;
        this.assetId = assetId;
        this.assetName = assetName;
        this.protocol = protocol;
        this.detail = detail;
    }

    public String getTrigger() { return trigger; }
    public String getSourceIp() { return sourceIp; }
    public String getAssetId() { return assetId; }
    public String getAssetName() { return assetName; }
    public String getProtocol() { return protocol; }
    public String getDetail() { return detail; }
}

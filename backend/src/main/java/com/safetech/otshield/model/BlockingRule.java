package com.safetech.otshield.model;

import jakarta.persistence.*;

@Entity
@Table(name = "blocking_rules")
public class BlockingRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "enabled")
    private Boolean enabled = true;

    @Column(name = "protocol")
    private String protocol; // exact match, optional

    @Column(name = "attack_type_contains")
    private String attackTypeContains; // substring match, optional

    @Column(name = "min_severity")
    private String minSeverity; // LOW, MEDIUM, HIGH, optional

    @Column(name = "min_reputation_score")
    private Integer minReputationScore; // optional

    @Column(name = "block_action")
    private Boolean block = true; // for future extensibility

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getAttackTypeContains() { return attackTypeContains; }
    public void setAttackTypeContains(String attackTypeContains) { this.attackTypeContains = attackTypeContains; }

    public String getMinSeverity() { return minSeverity; }
    public void setMinSeverity(String minSeverity) { this.minSeverity = minSeverity; }

    public Integer getMinReputationScore() { return minReputationScore; }
    public void setMinReputationScore(Integer minReputationScore) { this.minReputationScore = minReputationScore; }

    public Boolean getBlock() { return block; }
    public void setBlock(Boolean block) { this.block = block; }
}



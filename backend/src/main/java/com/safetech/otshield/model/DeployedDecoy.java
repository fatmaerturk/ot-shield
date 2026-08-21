package com.safetech.otshield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A decoy the operator deployed via one-click "self-configuring deception".
 * Persisted so deployed decoys survive a backend restart (the built-in fleet is
 * re-seeded in code; these user-added ones are reloaded from here). Keyed by the
 * canonical protocol name, so there is one deployed decoy per protocol.
 */
@Entity
@Table(name = "deployed_decoy")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeployedDecoy {

    @Id
    @Column(name = "protocol", length = 64)
    private String protocol;

    @Column(name = "vendor")
    private String vendor;

    @Column(name = "model")
    private String model;

    @Column(name = "port")
    private int port;
}

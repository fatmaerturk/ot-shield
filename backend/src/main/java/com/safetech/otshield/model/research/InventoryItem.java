package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * One entry in the bundle's component inventory.
 *
 * <p>HMGCC call alignment: "The tool must have the ability to understand
 * system architecture of a selected machine. A non-exhaustive list of
 * components to understand are the physical interface interactions,
 * data interfaces and protocols."
 *
 * <p>Rather than build four separate tables (components / ports /
 * services / protocols) we use a single entity with a {@link Kind}
 * discriminator. That keeps queries simple, the UI can filter by
 * {@code kind}, and Vulns' {@code componentRef} can later auto-complete
 * against a unified list.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "inventory_items", indexes = {
        @Index(name = "idx_inventory_bundle",      columnList = "bundle_id"),
        @Index(name = "idx_inventory_bundle_kind", columnList = "bundle_id,kind")
})
public class InventoryItem {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "bundle_id", nullable = false, length = 64)
    private String bundleId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private Kind kind;

    /** Short label shown in the list ("USB 3.0", "Port 102/TCP", "Modbus RTU"). */
    @Column(nullable = false, length = 256)
    private String name;

    /**
     * Longer free-text description - datasheet excerpts, config notes,
     * whatever the researcher wants captured with this row.
     */
    @Column(columnDefinition = "TEXT")
    private String details;

    /**
     * Free-text reference to a physical part, location, or vendor code
     * ("U4", "CN1 pin 3", "Siemens 6GK5...").
     */
    @Column(length = 256)
    private String reference;

    /**
     * Where this entry came from: "doc:{docId}", "thread:{threadId}",
     * "analyst:manual", etc. We keep it as free-text so the UI can
     * surface a breadcrumb without us committing to a strict join.
     */
    @Column(length = 512)
    private String source;

    /** Comma-separated tags, matches the convention used by Findings / Vulns. */
    @Column(length = 512)
    private String tags;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public enum Kind {
        /** A hardware component or assembly: chip, connector, board, module. */
        COMPONENT,
        /** A physical or logical port: "Port 102/TCP", "RJ45 MGMT", "Serial COM1". */
        PORT,
        /** A running service: "SSH (dropbear)", "Modbus slave", "Web UI". */
        SERVICE,
        /** A protocol family: "Modbus RTU", "S7Comm", "HTTP/1.1". */
        PROTOCOL
    }
}

package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.InventoryItem;
import com.safetech.otshield.model.research.InventoryItem.Kind;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface InventoryItemRepository extends JpaRepository<InventoryItem, String> {

    /** Full bundle inventory, most recently touched first. */
    List<InventoryItem> findByBundleIdOrderByUpdatedAtDesc(String bundleId);

    /** Single-kind listing. Used for the "Ports" vs "Components" view split. */
    List<InventoryItem> findByBundleIdAndKindOrderByUpdatedAtDesc(String bundleId, Kind kind);

    /**
     * Multi-kind listing so the Inventory tab can render
     * {@code COMPONENT + PROTOCOL} and the Ports tab can render
     * {@code PORT + SERVICE} without a second round-trip.
     */
    List<InventoryItem> findByBundleIdAndKindInOrderByUpdatedAtDesc(String bundleId, Collection<Kind> kinds);

    long countByBundleId(String bundleId);
}

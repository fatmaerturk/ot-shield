package com.safetech.otshield.service.research;

import com.safetech.otshield.dto.research.InventoryRequestDTOs.CreateRequest;
import com.safetech.otshield.dto.research.InventoryRequestDTOs.UpdateRequest;
import com.safetech.otshield.model.research.InventoryItem;
import com.safetech.otshield.model.research.InventoryItem.Kind;
import com.safetech.otshield.repository.research.InventoryItemRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * CRUD for the bundle component/port/service/protocol inventory.
 *
 * <p>Keeps the kind parsing defensive so a malformed client request
 * ends up as {@link Kind#COMPONENT} rather than a 500.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InventoryService {

    private final InventoryItemRepository repo;

    // ---- Reads --------------------------------------------------------

    public List<InventoryItem> list(String bundleId) {
        return repo.findByBundleIdOrderByUpdatedAtDesc(bundleId);
    }

    public List<InventoryItem> listByKinds(String bundleId, Collection<Kind> kinds) {
        if (kinds == null || kinds.isEmpty()) return list(bundleId);
        return repo.findByBundleIdAndKindInOrderByUpdatedAtDesc(bundleId, kinds);
    }

    public Optional<InventoryItem> get(String id) {
        return repo.findById(id);
    }

    public long count(String bundleId) {
        return repo.countByBundleId(bundleId);
    }

    // ---- Writes -------------------------------------------------------

    @Transactional
    public InventoryItem create(String bundleId, CreateRequest req) {
        if (bundleId == null || bundleId.isBlank()) {
            throw new IllegalArgumentException("bundleId is required");
        }
        if (req.name() == null || req.name().isBlank()) {
            throw new IllegalArgumentException("name is required");
        }
        LocalDateTime now = LocalDateTime.now();
        InventoryItem i = InventoryItem.builder()
                .id(UUID.randomUUID().toString())
                .bundleId(bundleId)
                .kind(parseKind(req.kind()))
                .name(req.name().trim())
                .details(req.details())
                .reference(req.reference())
                .source(req.source())
                .tags(req.tags())
                .createdAt(now)
                .updatedAt(now)
                .build();
        return repo.save(i);
    }

    @Transactional
    public Optional<InventoryItem> update(String id, UpdateRequest req) {
        return repo.findById(id).map(i -> {
            if (req.kind() != null) i.setKind(parseKind(req.kind()));
            if (req.name() != null && !req.name().isBlank()) i.setName(req.name().trim());
            if (req.details() != null) i.setDetails(req.details());
            if (req.reference() != null) i.setReference(req.reference());
            if (req.source() != null) i.setSource(req.source());
            if (req.tags() != null) i.setTags(req.tags());
            i.setUpdatedAt(LocalDateTime.now());
            return repo.save(i);
        });
    }

    @Transactional
    public void delete(String id) {
        repo.deleteById(id);
    }

    // ---- Helpers ------------------------------------------------------

    private static Kind parseKind(String raw) {
        if (raw == null || raw.isBlank()) return Kind.COMPONENT;
        try { return Kind.valueOf(raw); }
        catch (IllegalArgumentException e) { return Kind.COMPONENT; }
    }
}

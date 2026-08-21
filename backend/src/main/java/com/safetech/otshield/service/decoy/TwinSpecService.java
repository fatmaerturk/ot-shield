package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.TwinSpec;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.DpiEventRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds the decoy digital-twin blueprint for a discovered asset: its identity
 * (from the asset's real vendor/model, learned from OUI + MODBUS FC43) and the
 * behaviour it exhibits on the wire (the function codes observed in DPI). The
 * emulator serves exactly this, so a fingerprinting attacker sees the twin as
 * indistinguishable from the real device next to it.
 */
@Service
public class TwinSpecService {

    private final AssetRepository assetRepo;
    private final DpiEventRepository dpiRepo;
    private final ModbusTwinEmulator emulator;

    public TwinSpecService(AssetRepository assetRepo, DpiEventRepository dpiRepo, ModbusTwinEmulator emulator) {
        this.assetRepo = assetRepo;
        this.dpiRepo = dpiRepo;
        this.emulator = emulator;
    }

    /** Build the twin blueprint for an asset (null if the asset is unknown). */
    public TwinSpec buildSpec(String assetId) {
        Asset a = assetRepo.findById(assetId).orElse(null);
        if (a == null) return null;

        String proto = (a.getProtocol() != null && !a.getProtocol().isBlank()) ? a.getProtocol() : "MODBUS";

        Set<String> functions = new LinkedHashSet<>();
        long events = 0;
        try {
            List<Object[]> stats = dpiRepo.functionCodeStatsForNode(a.getIpAddress(), null, null);
            for (Object[] r : stats) {
                if (r[2] != null) functions.add(String.valueOf(r[2]));
                if (r[3] instanceof Number) events += ((Number) r[3]).longValue();
            }
        } catch (Exception ignored) { }

        String vendor = nn(a.getManufacturer(), "Unknown");
        String model = nn(a.getModel(), proto + " device");

        TwinSpec spec = TwinSpec.builder()
            .assetId(a.getId())
            .assetName(a.getName())
            .realIp(a.getIpAddress())
            .protocol(proto)
            .unitId(1)
            .vendor(vendor)
            .productCode(model)
            .modelName(model)
            .listenHost("127.0.0.1")
            .observedFunctions(new ArrayList<>(functions))
            .observedEvents(events)
            .build();

        // Reflect live emulator state if this asset's twin is the running one.
        TwinSpec running = emulator.activeSpec();
        if (emulator.isRunning() && running != null && a.getId().equals(running.getAssetId())) {
            spec.setListenHost(running.getListenHost());
            spec.setListenPort(running.getListenPort());
            spec.setRunning(true);
        }
        return spec;
    }

    private static String nn(String v, String fallback) {
        return (v == null || v.isBlank()) ? fallback : v;
    }
}

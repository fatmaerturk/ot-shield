package com.safetech.otshield.controller;

import com.safetech.otshield.dto.decoy.*;
import com.safetech.otshield.dto.cases.CreateCaseRequest;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.CaseCategory;
import com.safetech.otshield.model.CasePriority;
import com.safetech.otshield.service.CaseService;
import com.safetech.otshield.dto.decoy.TwinSpec;
import com.safetech.otshield.service.decoy.DecoyService;
import com.safetech.otshield.service.decoy.DecoyRecommendationService;
import com.safetech.otshield.service.decoy.TwinSpecService;
import com.safetech.otshield.service.decoy.ModbusTwinEmulator;
import com.safetech.otshield.service.decoy.DeceptionAdaptationService;
import com.safetech.otshield.service.decoy.BreachDetectedEvent;
import com.safetech.otshield.service.decoy.AttackPathService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/decoy")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class DecoyController {

    private final DecoyService service;
    private final DecoyRecommendationService recommendationService;
    private final CaseService caseService;
    private final TwinSpecService twinSpecService;
    private final ModbusTwinEmulator twinEmulator;
    private final DeceptionAdaptationService adaptationService;
    private final AttackPathService attackPathService;

    public DecoyController(DecoyService service, DecoyRecommendationService recommendationService,
                          CaseService caseService, TwinSpecService twinSpecService,
                          ModbusTwinEmulator twinEmulator, DeceptionAdaptationService adaptationService,
                          AttackPathService attackPathService) {
        this.service = service;
        this.recommendationService = recommendationService;
        this.caseService = caseService;
        this.twinSpecService = twinSpecService;
        this.twinEmulator = twinEmulator;
        this.adaptationService = adaptationService;
        this.attackPathService = attackPathService;
    }

    /** Predictive placement: attack paths to crown jewels + recommended decoy choke-points. */
    @GetMapping("/attack-paths")
    public ResponseEntity<Map<String, Object>> attackPaths() {
        return ResponseEntity.ok(attackPathService.buildAttackPaths());
    }

    // ---------- Adaptive (self-healing) deception ----------

    /** Recent auto-adaptations the platform performed in response to breaches. */
    @GetMapping("/adaptations")
    public ResponseEntity<List<AdaptationEventDTO>> adaptations(@RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(adaptationService.recent(limit));
    }

    @GetMapping("/adaptations/stats")
    public ResponseEntity<Map<String, Object>> adaptationStats() {
        return ResponseEntity.ok(adaptationService.stats());
    }

    /** Manually fire the self-healing loop (demo / testing). */
    @PostMapping("/adapt/test")
    public ResponseEntity<AdaptationEventDTO> adaptTest(
            @RequestParam String ip,
            @RequestParam(defaultValue = "MODBUS") String protocol,
            @RequestParam(required = false) String asset) {
        AdaptationEventDTO ev = adaptationService.adapt(new BreachDetectedEvent(
                "MANUAL", ip, null, asset != null ? asset : ("decoy-" + protocol), protocol, "Manual test trigger"));
        return ResponseEntity.ok(ev);
    }

    @GetMapping("/instances")
    public ResponseEntity<List<DecoyInstanceDTO>> listInstances() {
        return ResponseEntity.ok(service.listInstances());
    }

    /**
     * Adaptive decoy recommendations: which decoys to deploy so the deception
     * fabric mirrors THIS environment - derived from the ICS protocols actually
     * probed on the wire + the vendors of the operator's real assets, minus what
     * is already deployed. The seed of self-configuring deception.
     */
    @GetMapping("/recommendations")
    public ResponseEntity<List<Map<String, Object>>> recommendations() {
        return ResponseEntity.ok(recommendationService.buildRecommendations());
    }

    /**
     * Per-asset deception coverage: for each real asset, is its protocol mirrored
     * by a decoy and has it been probed on the fabric. Bridges the inventory to
     * the deception fabric.
     */
    @GetMapping("/asset-coverage")
    public ResponseEntity<List<Map<String, Object>>> assetCoverage() {
        return ResponseEntity.ok(recommendationService.buildAssetCoverage());
    }

    /** Alerts linked to an asset: attacks on the protocol it speaks + direct IP hits. */
    @GetMapping("/asset-alerts/{assetId}")
    public ResponseEntity<?> assetAlerts(@PathVariable String assetId) {
        return ResponseEntity.ok(recommendationService.alertsForAsset(assetId));
    }

    /** Segment-aware placement plan: where to place decoy twins, by subnet + Purdue level. */
    @GetMapping("/segment-plan")
    public ResponseEntity<List<Map<String, Object>>> segmentPlan() {
        return ResponseEntity.ok(recommendationService.buildSegmentPlan());
    }

    // ------------------------------------------------------------------ Twin ---
    // Decoy digital twin: clone a discovered asset into a MODBUS decoy. The
    // emulator binds ONLY to loopback (127.0.0.1) and is off unless started, so
    // it never exposes the host - it is for local verification/demo.

    /** The twin blueprint for an asset (identity + observed behaviour). */
    @GetMapping("/twin/{assetId}/spec")
    public ResponseEntity<TwinSpec> twinSpec(@PathVariable String assetId) {
        TwinSpec s = twinSpecService.buildSpec(assetId);
        return s == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(s);
    }

    /** Start the loopback-only twin emulator for an asset. Returns the bound spec. */
    @PostMapping("/twin/{assetId}/start")
    public ResponseEntity<?> twinStart(@PathVariable String assetId) {
        TwinSpec s = twinSpecService.buildSpec(assetId);
        if (s == null) return ResponseEntity.notFound().build();
        try {
            twinEmulator.start(s);
            return ResponseEntity.ok(s);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /** Stop the running twin emulator. */
    @PostMapping("/twin/stop")
    public ResponseEntity<Map<String, Object>> twinStop() {
        twinEmulator.stop();
        return ResponseEntity.ok(Map.of("running", false));
    }

    /** Current twin emulator status (running + active spec). */
    @GetMapping("/twin/status")
    public ResponseEntity<Map<String, Object>> twinStatus() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("running", twinEmulator.isRunning());
        m.put("spec", twinEmulator.activeSpec());
        return ResponseEntity.ok(m);
    }

    /** Interactions captured by the running twin (a write here is a breach signal). */
    @GetMapping("/twin/interactions")
    public ResponseEntity<List<Map<String, Object>>> twinInteractions() {
        return ResponseEntity.ok(twinEmulator.recentInteractions());
    }

    /**
     * One-click deploy a recommended decoy. Accepts the recommendation object
     * (protocol + suggestedVendor/Model/Port); registers the decoy in the fabric
     * and routes that protocol's real traffic to it. Returns the new decoy.
     */
    @PostMapping("/deploy")
    public ResponseEntity<DecoyInstanceDTO> deploy(@RequestBody Map<String, Object> body) {
        String protocol = (String) body.get("protocol");
        String vendor = (String) body.get("suggestedVendor");
        String model = (String) body.get("suggestedModel");
        Object portO = body.get("suggestedPort");
        Integer port = (portO instanceof Number) ? ((Number) portO).intValue() : null;
        try {
            return ResponseEntity.ok(service.deployDecoy(protocol, vendor, model, port));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /** Undeploy a previously deployed decoy (built-in fleet is not undeployable). */
    @DeleteMapping("/deploy/{protocol}")
    public ResponseEntity<Map<String, Object>> undeploy(@PathVariable String protocol) {
        boolean ok = service.undeployDecoy(protocol);
        return ok
            ? ResponseEntity.ok(Map.of("undeployed", true, "protocol", protocol))
            : ResponseEntity.badRequest().body(Map.of("undeployed", false, "reason", "not a user-deployed decoy"));
    }

    /**
     * Copilot tie-in: a grounded question asking whether this attacker's observed
     * behaviour threatens the operator's real assets. The frontend sends the
     * returned question to /api/assistant/chat for a cited RAG answer.
     */
    @GetMapping("/attackers/{ip}/threat-question")
    public ResponseEntity<Map<String, Object>> threatQuestion(@PathVariable String ip) {
        return ResponseEntity.ok(recommendationService.buildThreatQuestion(ip));
    }

    /**
     * Save a copilot threat assessment as a SOC case - closes the loop from
     * decoy detection to copilot analysis to an actionable, tracked incident
     * (and NIS2 evidence). Body: { assessment, protocols? }.
     */
    @PostMapping("/attackers/{ip}/save-case")
    public ResponseEntity<?> saveCase(@PathVariable String ip, @RequestBody Map<String, Object> body) {
        String assessment = String.valueOf(body.getOrDefault("assessment", "")).trim();

        Set<String> tags = new LinkedHashSet<>();
        tags.add("decoy");
        tags.add("copilot-assessment");
        tags.add("ip:" + ip);
        Object protos = body.get("protocols");
        if (protos instanceof List<?>) {
            for (Object p : (List<?>) protos) if (p != null) tags.add("proto:" + p.toString().toLowerCase());
        }

        String description = "Attacker " + ip + " engaged the OT decoy fabric.\n\n"
            + "Copilot threat assessment (grounded in the real asset inventory + ingested device manuals):\n\n"
            + (assessment.isEmpty() ? "(no assessment text provided)" : assessment);

        CreateCaseRequest req = CreateCaseRequest.builder()
            .title("Threat assessment: " + ip + " vs real assets")
            .description(description)
            .priority(CasePriority.HIGH)
            .severity(AlertSeverity.HIGH)
            .category(CaseCategory.OT_DISRUPTION)
            .reporterName("OTShield Copilot")
            .tags(tags)
            .build();

        return ResponseEntity.ok(caseService.create(req));
    }

    @GetMapping("/instances/{id}")
    public ResponseEntity<DecoyInstanceDTO> getInstance(@PathVariable String id) {
        DecoyInstanceDTO d = service.getInstance(id);
        return d == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(d);
    }

    @GetMapping("/engagements")
    public ResponseEntity<List<EngagementDTO>> listEngagements(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String decoyId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(service.listEngagements(status, decoyId, page, size));
    }

    @GetMapping("/engagements/{id}")
    public ResponseEntity<EngagementDTO> getEngagement(@PathVariable String id) {
        EngagementDTO e = service.getEngagement(id);
        return e == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(e);
    }

    @GetMapping("/attackers/{ip}")
    public ResponseEntity<AttackerProfileDTO> getAttacker(@PathVariable String ip) {
        AttackerProfileDTO a = service.getAttacker(ip);
        return a == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(a);
    }

    @GetMapping("/stats")
    public ResponseEntity<DecoyStatsDTO> stats() {
        return ResponseEntity.ok(service.computeStats());
    }

    @PostMapping("/actions")
    public ResponseEntity<DecoyActionResultDTO> applyAction(@RequestBody DecoyActionRequest req) {
        String actor = currentUsername();
        DecoyActionResultDTO result = service.applyAction(req, actor);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/actions/recent")
    public ResponseEntity<List<DecoyActionResultDTO>> recentActions(
            @RequestParam(defaultValue = "20") int limit) {
        return ResponseEntity.ok(service.recentActions(limit));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "healthy",
                "service", "decoy-layer",
                "instances", service.listInstances().size()
        ));
    }

    private String currentUsername() {
        try {
            Authentication a = SecurityContextHolder.getContext().getAuthentication();
            return a != null ? a.getName() : "anonymous";
        } catch (Exception e) {
            return "anonymous";
        }
    }
}

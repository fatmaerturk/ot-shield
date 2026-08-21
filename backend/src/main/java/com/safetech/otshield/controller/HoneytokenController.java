package com.safetech.otshield.controller;

import com.safetech.otshield.model.Honeytoken;
import com.safetech.otshield.model.HoneytokenTrip;
import com.safetech.otshield.service.HoneytokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Honeytokens (decoy lures): generate them, list trips, and expose the public
 * beacon endpoint a planted URL/document calls home to. The beacon is
 * unauthenticated by design - the whole point is that an intruder's tool hits it
 * with no credentials.
 */
@RestController
@RequestMapping("/api/honeytoken")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class HoneytokenController {

    private final HoneytokenService service;

    // 1x1 transparent GIF, so a planted <img> beacon in a doc/email renders cleanly.
    private static final byte[] PIXEL = new byte[]{
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, (byte) 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x21, (byte) 0xF9, 0x04, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x02, 0x02, 0x44, 0x01, 0x00, 0x3B
    };

    public HoneytokenController(HoneytokenService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<Honeytoken>> list() {
        return ResponseEntity.ok(service.list());
    }

    @PostMapping
    public ResponseEntity<Honeytoken> create(@RequestBody Map<String, Object> body) {
        String type = str(body.get("type"));
        String label = str(body.get("label"));
        String note = str(body.get("note"));
        return ResponseEntity.ok(service.create(type, label, note));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        boolean ok = service.delete(id);
        return ok ? ResponseEntity.ok(Map.of("deleted", true))
                  : ResponseEntity.badRequest().body(Map.of("deleted", false));
    }

    @GetMapping("/trips")
    public ResponseEntity<List<HoneytokenTrip>> trips() {
        return ResponseEntity.ok(service.recentTrips());
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> stats() {
        return ResponseEntity.ok(service.stats());
    }

    /**
     * Public beacon: a planted lure was opened. Records the real source IP + user
     * agent and returns a transparent pixel. Never leaks whether the id is valid.
     */
    @GetMapping("/hit/{id}")
    public ResponseEntity<byte[]> hit(@PathVariable String id, HttpServletRequest request) {
        try {
            service.recordCallbackHit(id, clientIp(request),
                request.getHeader("User-Agent"), request.getHeader("Referer"));
        } catch (Exception ignored) { }
        return ResponseEntity.ok()
            .contentType(MediaType.IMAGE_GIF)
            .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
            .body(PIXEL);
    }

    private static String clientIp(HttpServletRequest r) {
        String xff = r.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return r.getRemoteAddr();
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }
}

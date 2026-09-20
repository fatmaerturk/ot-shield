package com.safetech.otshield.controller;

import com.safetech.otshield.service.GeoIpService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Offline IP geolocation, backed by the local MaxMind GeoLite2 database via
 * {@link GeoIpService}. This replaces the frontend's previous direct calls to
 * the third-party ipapi.co service, so attacker/source IPs never leave the
 * platform and the product stays offline / air-gap capable.
 */
@RestController
@RequestMapping("/api/geo")
@RequiredArgsConstructor
public class GeoController {

    private final GeoIpService geoIpService;

    /** Look up a single IP; returns { country, city, lat, lon } (nulls if the
     *  database is missing or the address is not found). */
    @GetMapping("/{ip}")
    public ResponseEntity<Map<String, Object>> lookup(@PathVariable String ip) {
        return ResponseEntity.ok(geoIpService.lookup(ip).toMap());
    }
}

package com.safetech.otshield.service;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Offline IP geolocation using the MaxMind GeoLite2 City database.
 *
 * The .mmdb file is NOT bundled with the repository (it's ~70MB and has its
 * own license). Download GeoLite2-City.mmdb from
 * https://dev.maxmind.com/geoip/geolite2-free-geolocation-data (free account)
 * and place it at: backend/geoip/GeoLite2-City.mmdb
 *
 * If the file is missing, every lookup returns UNKNOWN silently and the
 * backend keeps working — geolocation just stays empty.
 */
@Service
public class GeoIpService {

    private static final Logger log = LoggerFactory.getLogger(GeoIpService.class);

    public static class GeoInfo {
        public final String country;
        public final String city;
        public final Double lat;
        public final Double lon;

        public GeoInfo(String country, String city, Double lat, Double lon) {
            this.country = country;
            this.city = city;
            this.lat = lat;
            this.lon = lon;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new java.util.HashMap<>();
            m.put("country", country);
            m.put("city", city);
            m.put("lat", lat);
            m.put("lon", lon);
            return m;
        }
    }

    public static final GeoInfo UNKNOWN = new GeoInfo(null, null, null, null);

    @Value("${geoip.database.path:backend/geoip/GeoLite2-City.mmdb}")
    private String databasePath;

    private DatabaseReader reader;
    private final Map<String, GeoInfo> cache = new ConcurrentHashMap<>();
    private volatile boolean available = false;

    @PostConstruct
    public void init() {
        // Resolve path — try both absolute and a few common working dirs
        File f = new File(databasePath);
        if (!f.exists()) {
            // If backend runs from backend/ dir, the 'backend/' prefix duplicates
            File alt = new File(databasePath.replaceFirst("^backend/", ""));
            if (alt.exists()) {
                f = alt;
            }
        }
        if (!f.exists()) {
            log.warn("GeoIP database not found at '{}'. Geolocation lookups will return UNKNOWN. " +
                    "Download GeoLite2-City.mmdb from https://www.maxmind.com/ and place it at '{}'.",
                databasePath, f.getAbsolutePath());
            available = false;
            return;
        }
        try {
            reader = new DatabaseReader.Builder(f).build();
            available = true;
            log.info("GeoIP database loaded: {}", f.getAbsolutePath());
        } catch (Exception e) {
            log.error("Failed to load GeoIP database '{}': {}", f.getAbsolutePath(), e.getMessage());
            available = false;
        }
    }

    @PreDestroy
    public void close() {
        if (reader != null) {
            try { reader.close(); } catch (Exception ignored) {}
        }
    }

    public boolean isAvailable() {
        return available;
    }

    /** Look up an IP address. Returns UNKNOWN if the database is missing or the IP isn't routable. */
    public GeoInfo lookup(String ip) {
        if (ip == null || ip.isBlank()) return UNKNOWN;

        // Private / loopback ranges don't resolve to real coordinates. Give them a
        // stable pseudo-location near the decoy so the map still shows them — this
        // is essential for Conpot simulation mode where all source IPs are RFC1918.
        if (isPrivateOrLoopback(ip)) {
            GeoInfo cached = cache.get(ip);
            if (cached != null) return cached;
            GeoInfo pseudo = pseudoLocationForPrivate(ip);
            if (cache.size() < 50_000) cache.put(ip, pseudo);
            return pseudo;
        }

        if (!available) return UNKNOWN;

        GeoInfo cached = cache.get(ip);
        if (cached != null) return cached;

        try {
            CityResponse resp = reader.city(InetAddress.getByName(ip));
            String country = resp.getCountry() != null ? resp.getCountry().getName() : null;
            String city = resp.getCity() != null ? resp.getCity().getName() : null;
            Double lat = resp.getLocation() != null ? resp.getLocation().getLatitude() : null;
            Double lon = resp.getLocation() != null ? resp.getLocation().getLongitude() : null;
            GeoInfo info = new GeoInfo(country, city, lat, lon);
            if (cache.size() < 50_000) cache.put(ip, info);
            return info;
        } catch (Exception e) {
            if (cache.size() < 50_000) cache.put(ip, UNKNOWN);
            return UNKNOWN;
        }
    }

    /**
     * Generate a label for a private/loopback/TEST-NET IP. These addresses
     * have no real-world coordinates, so we tag them with their network
     * function so the dashboard makes it obvious *why* there is no country —
     * instead of misleadingly attributing them to some random world city.
     *
     *   127/8                       → "Loopback (local host)"
     *   10/8, 172.16/12, 192.168/16 → "Internal (RFC 1918)"
     *   IPv6 link-local / ULA       → "Internal (IPv6 ULA / link-local)"
     *   192.0.2/24, 198.51.100/24,
     *   203.0.113/24                → "Documentation (RFC 5737)"
     */
    private GeoInfo pseudoLocationForPrivate(String ip) {
        if (ip == null) return UNKNOWN;
        if (ip.startsWith("127.") || ip.equals("::1")) {
            return new GeoInfo("Loopback (local host)", "127.0.0.1", null, null);
        }
        if (ip.startsWith("192.0.2.") || ip.startsWith("198.51.100.") || ip.startsWith("203.0.113.")) {
            return new GeoInfo("Documentation (RFC 5737)", ip, null, null);
        }
        if (ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) {
            return new GeoInfo("Internal (IPv6 ULA / link-local)", ip, null, null);
        }
        // RFC 1918: 10/8, 172.16/12, 192.168/16
        return new GeoInfo("Internal (RFC 1918)", ip, null, null);
    }

    private static final class SimCity {
        final String city; final String country; final double lat; final double lon;
        SimCity(String city, String country, double lat, double lon) {
            this.city = city; this.country = country; this.lat = lat; this.lon = lon;
        }
    }

    // 30 cities spanning every continent → kept for an optional future
    // "simulate global attacks" toggle; not currently used.
    @SuppressWarnings("unused")
    private static final SimCity[] SIM_CITIES = new SimCity[] {
        new SimCity("Moscow", "Russia", 55.7558, 37.6176),
        new SimCity("Saint Petersburg", "Russia", 59.9311, 30.3609),
        new SimCity("Beijing", "China", 39.9042, 116.4074),
        new SimCity("Shanghai", "China", 31.2304, 121.4737),
        new SimCity("Shenzhen", "China", 22.5431, 114.0579),
        new SimCity("Pyongyang", "North Korea", 39.0392, 125.7625),
        new SimCity("Tehran", "Iran", 35.6892, 51.3890),
        new SimCity("Kyiv", "Ukraine", 50.4501, 30.5234),
        new SimCity("Minsk", "Belarus", 53.9006, 27.5590),
        new SimCity("Istanbul", "Turkey", 41.0082, 28.9784),
        new SimCity("Berlin", "Germany", 52.5200, 13.4050),
        new SimCity("Paris", "France", 48.8566, 2.3522),
        new SimCity("London", "United Kingdom", 51.5074, -0.1278),
        new SimCity("Amsterdam", "Netherlands", 52.3676, 4.9041),
        new SimCity("Stockholm", "Sweden", 59.3293, 18.0686),
        new SimCity("Bucharest", "Romania", 44.4268, 26.1025),
        new SimCity("Sofia", "Bulgaria", 42.6977, 23.3219),
        new SimCity("Washington D.C.", "United States", 38.9072, -77.0369),
        new SimCity("New York", "United States", 40.7128, -74.0060),
        new SimCity("San Francisco", "United States", 37.7749, -122.4194),
        new SimCity("Toronto", "Canada", 43.6532, -79.3832),
        new SimCity("Mexico City", "Mexico", 19.4326, -99.1332),
        new SimCity("São Paulo", "Brazil", -23.5505, -46.6333),
        new SimCity("Buenos Aires", "Argentina", -34.6037, -58.3816),
        new SimCity("Mumbai", "India", 19.0760, 72.8777),
        new SimCity("Singapore", "Singapore", 1.3521, 103.8198),
        new SimCity("Jakarta", "Indonesia", -6.2088, 106.8456),
        new SimCity("Tokyo", "Japan", 35.6762, 139.6503),
        new SimCity("Seoul", "South Korea", 37.5665, 126.9780),
        new SimCity("Lagos", "Nigeria", 6.5244, 3.3792),
        new SimCity("Johannesburg", "South Africa", -26.2041, 28.0473),
        new SimCity("Sydney", "Australia", -33.8688, 151.2093),
    };

    /**
     * True for addresses that cannot be geolocated publicly, including:
     *   - RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
     *   - Loopback (127/8, ::1)
     *   - IPv6 link-local / ULA (fe80::/10, fc00::/7)
     *   - RFC 5737 documentation / TEST-NET ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
     *     — these are what Conpot's simulation mode generates, so we treat them
     *     as "simulated internal" rather than "unknown".
     */
    private boolean isPrivateOrLoopback(String ip) {
        if (ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("192.168.")) return true;
        if (ip.startsWith("172.")) {
            try {
                int second = Integer.parseInt(ip.split("\\.")[1]);
                if (second >= 16 && second <= 31) return true;
            } catch (Exception ignored) {}
        }
        // RFC 5737 TEST-NET ranges — used by Conpot simulation
        if (ip.startsWith("192.0.2.")) return true;
        if (ip.startsWith("198.51.100.")) return true;
        if (ip.startsWith("203.0.113.")) return true;
        if (ip.equals("0.0.0.0") || ip.equals("255.255.255.255")) return true;
        // IPv6 loopback / link-local / unique-local
        if (ip.equals("::1") || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
        return false;
    }
}

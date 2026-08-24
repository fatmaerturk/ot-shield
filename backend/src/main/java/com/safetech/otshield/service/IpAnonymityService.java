package com.safetech.otshield.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Classifies the NATURE of an attacker IP (the connection type), not a
 * guaranteed "VPN yes/no" - that cannot be derived from an IP alone. It answers
 * the practical triage question for the internet-exposed decoy: is this source
 * an anonymised / automated origin (Tor, hosting/datacenter, VPN provider) or an
 * apparently-direct residential endpoint?
 *
 * <p>Signals, all real (no fabrication) and offline-first:
 * <ul>
 *   <li><b>Tor exit node</b> - the public Tor exit list (definitive when it fires).</li>
 *   <li><b>ASN / network owner</b> - via {@link GeoIpService#lookupAsn}; the org
 *       name is matched against known hosting/datacenter and VPN-provider tokens.
 *       A datacenter/VPN ASN means the traffic is not a normal residential user.</li>
 * </ul>
 *
 * <p>Honest blind spots surfaced to the caller (never hidden): a <b>corporate
 * VPN egress</b> looks like a normal org IP and cannot be flagged as VPN from the
 * IP; a <b>residential proxy</b> looks residential and needs a specialised
 * database to catch. Where there is no basis (no ASN DB, private/loopback IP),
 * the category is NOT_ASSESSED / INTERNAL - never a guess.
 */
@Service
public class IpAnonymityService {

    private static final Logger log = LoggerFactory.getLogger(IpAnonymityService.class);

    public enum Category { TOR_EXIT, VPN_PROVIDER, HOSTING_DATACENTER, RESIDENTIAL_ISP, INTERNAL, NOT_ASSESSED }
    public enum Confidence { HIGH, MEDIUM, LOW, NONE }

    public static final class AnonymityInfo {
        public final Category category;
        public final Confidence confidence;
        public final List<String> signals;
        public final Long asnNumber;
        public final String asnOrg;
        public final String note;

        AnonymityInfo(Category category, Confidence confidence, List<String> signals,
                      Long asnNumber, String asnOrg, String note) {
            this.category = category;
            this.confidence = confidence;
            this.signals = signals;
            this.asnNumber = asnNumber;
            this.asnOrg = asnOrg;
            this.note = note;
        }

        /** True when the source is anonymised / not an apparently-direct residential endpoint. */
        public boolean isAnonymized() {
            return category == Category.TOR_EXIT || category == Category.VPN_PROVIDER
                    || category == Category.HOSTING_DATACENTER;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("category", category.name());
            m.put("label", label());
            m.put("confidence", confidence.name());
            m.put("anonymized", isAnonymized());
            m.put("signals", signals);
            m.put("asn", asnNumber);
            m.put("asnOrg", asnOrg);
            m.put("note", note);
            return m;
        }

        public String label() {
            switch (category) {
                case TOR_EXIT: return "Tor exit node";
                case VPN_PROVIDER: return "VPN provider";
                case HOSTING_DATACENTER: return "Hosting / datacenter";
                case RESIDENTIAL_ISP: return "Residential ISP (appears direct)";
                case INTERNAL: return "Internal / loopback";
                default: return "Not assessed";
            }
        }
    }

    // Strong hosting/datacenter/cloud network-owner tokens (lower-cased match on ASN org).
    private static final String[] DATACENTER_TOKENS = {
        "amazon", "aws", "google", "microsoft", "azure", "oracle", "alibaba", "tencent",
        "digitalocean", "digital ocean", "ovh", "hetzner", "linode", "akamai", "vultr",
        "constant company", "choopa", "leaseweb", "m247", "contabo", "scaleway", "gcore",
        "g-core", "cloudflare", "datacamp", "cdn77", "hostwinds", "colocrossing", "quadranet",
        "psychz", "gigenet", "serverius", "worldstream", "servers.com", "server4you", "online sas",
        "online s.a.s", "ip volume", "as-vultr", "hosting", "datacenter", "data center",
        "colocation", " colo", "dedicated server", "cloud", "vps", "server hosting", "webhosting",
        "web hosting", "data services", "internet services provider corp"
    };

    // VPN-provider network-owner tokens (checked before generic datacenter so they win).
    private static final String[] VPN_TOKENS = {
        "nordvpn", "mullvad", "expressvpn", "private internet access", "surfshark", "cyberghost",
        "protonvpn", "proton ag", "windscribe", "ipvanish", "hide.me", "perfect privacy",
        "azirevpn", "ovpn", "purevpn", "vpn", "tunnelbear", "torguard", "privado"
    };

    @Value("${ipintel.tor.exit-list-url:https://check.torproject.org/torbulkexitlist}")
    private String torListUrl;

    private final GeoIpService geoIpService;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(8))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private volatile Set<String> torExits = ConcurrentHashMap.newKeySet();
    private volatile Instant torUpdatedAt = null;

    public IpAnonymityService(GeoIpService geoIpService) {
        this.geoIpService = geoIpService;
    }

    @PostConstruct
    public void init() {
        // Refresh off the boot path so a slow/blocked fetch never delays startup.
        // The @Scheduled task with a short initial delay does the first load.
    }

    /** Hourly refresh of the Tor exit list; first run ~15s after boot. */
    @Scheduled(initialDelay = 15_000, fixedDelay = 3_600_000)
    public void refreshTorList() {
        if (torListUrl == null || torListUrl.isBlank()) return;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(torListUrl))
                    .timeout(Duration.ofSeconds(15))
                    .header("User-Agent", "OTShield-IpIntel/1.0")
                    .GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200 && resp.body() != null && !resp.body().isBlank()) {
                Set<String> fresh = ConcurrentHashMap.newKeySet();
                for (String line : resp.body().split("\\r?\\n")) {
                    String ip = line.trim();
                    if (!ip.isEmpty() && !ip.startsWith("#")) fresh.add(ip);
                }
                if (!fresh.isEmpty()) {
                    torExits = fresh;
                    torUpdatedAt = Instant.now();
                    log.info("Tor exit list refreshed: {} nodes", fresh.size());
                }
            } else {
                log.warn("Tor exit list fetch returned HTTP {} - keeping last snapshot ({} nodes)",
                        resp.statusCode(), torExits.size());
            }
        } catch (Exception e) {
            log.warn("Tor exit list fetch failed ({}) - keeping last snapshot ({} nodes)",
                    e.getMessage(), torExits.size());
        }
    }

    public boolean isTorExit(String ip) {
        return ip != null && torExits.contains(ip.trim());
    }

    /** Classify one IP. Never throws; returns NOT_ASSESSED / INTERNAL where there is no basis. */
    public AnonymityInfo classify(String ip) {
        List<String> signals = new ArrayList<>();
        if (ip == null || ip.isBlank()) {
            return new AnonymityInfo(Category.NOT_ASSESSED, Confidence.NONE, signals, null, null,
                    "No source IP.");
        }
        if (geoIpService.isPrivateOrLoopbackPublic(ip)) {
            return new AnonymityInfo(Category.INTERNAL, Confidence.HIGH, List.of("private-or-loopback"),
                    null, null, "Private / loopback address - not internet-routable, so not classifiable.");
        }

        // 1) Tor exit node - definitive when it fires.
        if (isTorExit(ip)) {
            signals.add("tor-exit-node");
        }

        // 2) ASN / network owner.
        GeoIpService.Asn asn = geoIpService.lookupAsn(ip);
        Long asnNum = asn != null ? asn.number : null;
        String org = asn != null ? asn.org : null;
        String orgLc = org == null ? "" : org.toLowerCase();

        boolean vpnHit = matchesAny(orgLc, VPN_TOKENS);
        boolean dcHit = matchesAny(orgLc, DATACENTER_TOKENS);

        if (signals.contains("tor-exit-node")) {
            return new AnonymityInfo(Category.TOR_EXIT, Confidence.HIGH, signals, asnNum, org,
                    "Listed on the public Tor exit-node list. Traffic is anonymised.");
        }
        if (vpnHit) {
            signals.add("asn-vpn-provider");
            return new AnonymityInfo(Category.VPN_PROVIDER, Confidence.HIGH, signals, asnNum, org,
                    "Network owner is a known VPN provider. This is a commercial-VPN egress, not a residential endpoint.");
        }
        if (dcHit) {
            signals.add("asn-hosting-datacenter");
            return new AnonymityInfo(Category.HOSTING_DATACENTER, Confidence.HIGH, signals, asnNum, org,
                    "Network owner is a hosting / datacenter / cloud provider. This is not a normal residential user (VPN exit, cloud VPS, or automated scanner).");
        }
        if (org != null && !org.isBlank()) {
            signals.add("asn-residential");
            return new AnonymityInfo(Category.RESIDENTIAL_ISP, Confidence.MEDIUM, signals, asnNum, org,
                    "Network owner looks like a residential / telco ISP, so the source appears direct. Note: this is not proof of no VPN - a corporate-VPN egress looks like a normal ISP/org IP, and residential proxies also look residential.");
        }

        // No ASN basis (DB missing or lookup empty) and not Tor.
        return new AnonymityInfo(Category.NOT_ASSESSED, Confidence.NONE, signals, asnNum, org,
                geoIpService.isAsnAvailable()
                        ? "No network-owner record for this IP."
                        : "ASN database not loaded - place GeoLite2-ASN.mmdb in backend/geoip to enable classification.");
    }

    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("asnDbAvailable", geoIpService.isAsnAvailable());
        m.put("torNodes", torExits.size());
        m.put("torUpdatedAt", torUpdatedAt == null ? null : torUpdatedAt.toString());
        return m;
    }

    private static boolean matchesAny(String haystackLc, String[] tokens) {
        if (haystackLc == null || haystackLc.isEmpty()) return false;
        for (String t : tokens) {
            if (haystackLc.contains(t)) return true;
        }
        return false;
    }
}

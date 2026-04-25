package com.safetech.otshield.service.assistant;

import com.safetech.otshield.model.research.ResearchDocument.SourceType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, zero-LLM cross-check over the passages RAG pulled for
 * one question. The HMGCC brief explicitly asks for "source cross-check"
 * so a researcher can see when a vendor manual and a forum post are
 * telling them different things about the same system. This service
 * delivers that as a per-answer list of consistency warnings.
 *
 * <p>We keep the matching coarse on purpose:
 * <ul>
 *   <li>Only look at a small set of "facty" token kinds (ports, IPs,
 *       CVE ids, passwords, and numeric values with common units).</li>
 *   <li>Group tokens by a normalised <em>subject</em>: the nearest
 *       meaningful phrase before the token. If two passages mention
 *       "default port" but with different numbers, that's a warning;
 *       if they talk about unrelated ports they're not in conflict.</li>
 *   <li>Only flag a warning when the disagreeing passages come from
 *       <em>different</em> source-type classes. A vendor manual
 *       contradicting itself is probably a misread chunk, not a
 *       real discrepancy worth nagging the user about.</li>
 * </ul>
 *
 * <p>This class is intentionally stateless so it can be wired into
 * AssistantController as a singleton and called on the streaming
 * thread without locking.
 */
@Component
@Slf4j
public class SourceCrossCheckService {

    /**
     * One flagged conflict surfaced to the UI. {@code claim} is a
     * short human-readable subject ("default port", "CVE reference"),
     * {@code values} is the distinct values that showed up across
     * source types, and {@code conflictingCitations} are the citation
     * indices (1-based, matching the bracket markers) the UI should
     * highlight.
     */
    public record ConsistencyWarning(
            String claim,
            List<ValueSource> values,
            List<Integer> conflictingCitations
    ) {}

    /**
     * One (value, source-type, citation-index) triple inside a warning.
     * Plural form lets the UI show "Manual says X, Forum says Y".
     */
    public record ValueSource(String value, String sourceType, int citationIndex) {}

    /**
     * Token extractor kinds we currently understand. Adding a new kind
     * means adding a pattern + a subject-preamble regex to the map
     * below - the rest of the pipeline is kind-agnostic.
     */
    private static final class Kind {
        static final String PORT = "port";
        static final String CVE  = "cve";
        static final String IP   = "ip";
        static final String PWD  = "password";
        static final String VERSION = "version";
    }

    /**
     * Patterns are intentionally lenient and case-insensitive. The
     * first capture group must be the value itself.
     */
    private static final Map<String, Pattern> VALUE_PATTERNS = new LinkedHashMap<>();
    static {
        // "port 23", "port: 23", "TCP/23", "Modbus port 502"
        VALUE_PATTERNS.put(Kind.PORT,
                Pattern.compile("\\bports?\\s*[:=]?\\s*(\\d{1,5})\\b", Pattern.CASE_INSENSITIVE));
        // CVE-2023-12345
        VALUE_PATTERNS.put(Kind.CVE,
                Pattern.compile("(CVE-\\d{4}-\\d{4,7})", Pattern.CASE_INSENSITIVE));
        // IPv4 dotted quad (very rough; we don't care about full validity)
        VALUE_PATTERNS.put(Kind.IP,
                Pattern.compile("\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b"));
        // "default password is admin", "pwd: admin123"
        VALUE_PATTERNS.put(Kind.PWD,
                Pattern.compile("(?:default\\s+)?(?:password|pwd|passphrase)\\s*(?:is|:|=)\\s*[\"']?([A-Za-z0-9_!@#$%^&*-]{3,32})[\"']?",
                        Pattern.CASE_INSENSITIVE));
        // "firmware v1.2.3", "version 4.5"
        VALUE_PATTERNS.put(Kind.VERSION,
                Pattern.compile("\\b(?:firmware|version|ver\\.?)\\s*(v?\\d+(?:\\.\\d+){1,3})\\b",
                        Pattern.CASE_INSENSITIVE));
    }

    /**
     * Short, human-readable label per kind. Shown as the warning's
     * primary "claim" text. We also reuse this as part of the subject
     * key so two unrelated ports (port 23 for telnet vs port 502 for
     * Modbus) group separately based on the context word preceding
     * the value.
     */
    private static final Map<String, String> KIND_LABEL = Map.of(
            Kind.PORT, "port",
            Kind.CVE,  "CVE reference",
            Kind.IP,   "IP address",
            Kind.PWD,  "default password",
            Kind.VERSION, "firmware / version"
    );

    /** Input envelope: one retrieved passage to inspect. */
    public record Passage(int citationIndex, String sourceLabel, String sourceType, String text) {}

    /**
     * Run the cross-check. Returns an empty list when the corpus is
     * unanimous (or when fewer than two source-type classes are even
     * represented in this retrieval — without that we can't have a
     * cross-source conflict by construction).
     */
    public List<ConsistencyWarning> check(Collection<Passage> passages) {
        if (passages == null || passages.size() < 2) return List.of();

        // Distinct source types seen. If there's only one class the
        // check is pointless (anything we'd flag is same-source
        // contradiction, which usually means we mis-chunked).
        Set<String> distinctTypes = new HashSet<>();
        for (Passage p : passages) {
            if (p.sourceType() != null && !p.sourceType().isBlank()) {
                distinctTypes.add(p.sourceType());
            }
        }
        if (distinctTypes.size() < 2) return List.of();

        // Collect raw observations first, with their subject keyword
        // sets. We'll bucket them by "same kind + overlapping keyword
        // set" rather than by strict subject-string equality, because
        // two passages almost never phrase the same claim identically.
        List<Observation> allObs = new ArrayList<>();
        for (Passage p : passages) {
            String text = p.text() == null ? "" : p.text();
            for (Map.Entry<String, Pattern> e : VALUE_PATTERNS.entrySet()) {
                Matcher m = e.getValue().matcher(text);
                while (m.find()) {
                    String value = m.group(1);
                    if (value == null || value.isBlank()) continue;
                    Set<String> subject = subjectKeywords(text, m.start());
                    allObs.add(new Observation(e.getKey(), normalise(value), subject, p));
                }
            }
        }

        // Greedy bucketing: for each observation, drop it into the
        // first existing bucket of the same kind whose subject set
        // overlaps by at least one keyword. Otherwise open a new
        // bucket. For a retrieval of 4 passages this is O(n^2) in
        // a handful of observations - not a concern.
        Map<String, List<Observation>> bySubject = new LinkedHashMap<>();
        for (Observation o : allObs) {
            String match = null;
            for (Map.Entry<String, List<Observation>> bucket : bySubject.entrySet()) {
                Observation head = bucket.getValue().get(0);
                if (!head.kind.equals(o.kind)) continue;
                if (subjectsOverlap(head.subjectKeywords, o.subjectKeywords)) {
                    match = bucket.getKey();
                    break;
                }
            }
            if (match == null) {
                match = o.kind + "|" + String.join(",", new java.util.TreeSet<>(o.subjectKeywords));
            }
            bySubject.computeIfAbsent(match, k -> new ArrayList<>()).add(o);
        }

        List<ConsistencyWarning> out = new ArrayList<>();
        for (Map.Entry<String, List<Observation>> entry : bySubject.entrySet()) {
            List<Observation> obs = entry.getValue();
            if (obs.size() < 2) continue;

            // Group observations by distinct value. If there's only
            // one distinct value, no conflict.
            Map<String, List<Observation>> byValue = new LinkedHashMap<>();
            for (Observation o : obs) {
                byValue.computeIfAbsent(o.value, k -> new ArrayList<>()).add(o);
            }
            if (byValue.size() < 2) continue;

            // Require that the conflict spans source-type classes.
            // Two forum posts disagreeing aren't as interesting as a
            // forum vs a vendor manual.
            Set<String> typesInvolved = new HashSet<>();
            for (Observation o : obs) {
                if (o.passage.sourceType() != null) typesInvolved.add(o.passage.sourceType());
            }
            if (typesInvolved.size() < 2) continue;

            List<ValueSource> values = new ArrayList<>();
            Set<Integer> citations = new java.util.LinkedHashSet<>();
            for (Map.Entry<String, List<Observation>> vEntry : byValue.entrySet()) {
                // Pick the first observation with the "most trusted"
                // source type as the representative for this value.
                Observation rep = pickRepresentative(vEntry.getValue());
                values.add(new ValueSource(
                        rep.value,
                        rep.passage.sourceType() == null ? "UNKNOWN" : rep.passage.sourceType(),
                        rep.passage.citationIndex()
                ));
                for (Observation o : vEntry.getValue()) {
                    citations.add(o.passage.citationIndex());
                }
            }

            // Derive a short human-readable claim: "port — default
            // modbus". Keywords are the intersection across every
            // observation in this bucket so the label captures what
            // they all agreed was the subject, nothing wider.
            String kindLabel = KIND_LABEL.getOrDefault(
                    obs.get(0).kind, obs.get(0).kind);
            Set<String> shared = null;
            for (Observation o : obs) {
                if (shared == null) {
                    shared = new HashSet<>(o.subjectKeywords);
                } else {
                    shared.retainAll(o.subjectKeywords);
                }
            }
            String subject = (shared == null || shared.isEmpty())
                    ? ""
                    : new java.util.TreeSet<>(shared).stream()
                            .limit(3)
                            .reduce((a, b) -> a + " " + b)
                            .orElse("");
            String claim = subject.isBlank()
                    ? kindLabel
                    : kindLabel + " — " + subject;

            out.add(new ConsistencyWarning(claim, values, new ArrayList<>(citations)));
        }

        if (log.isDebugEnabled()) {
            log.debug("Cross-check: {} passages across {} source types -> {} warnings",
                    passages.size(), distinctTypes.size(), out.size());
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private record Observation(String kind, String value, Set<String> subjectKeywords, Passage passage) {}

    /**
     * Two keyword sets are considered the same subject when they share
     * at least one meaningful keyword, OR when both are empty (in which
     * case we fall back to kind-only grouping and let the downstream
     * value comparison decide). The second case is how "port 23" vs
     * "port 23" with no context still lands in the same bucket.
     */
    private static boolean subjectsOverlap(Set<String> a, Set<String> b) {
        if (a == null || b == null) return false;
        if (a.isEmpty() && b.isEmpty()) return true;
        for (String k : a) {
            if (b.contains(k)) return true;
        }
        return false;
    }

    /**
     * Extract the meaningful keyword set from the ~60 chars preceding
     * the matched value. Drops stopwords and tokens shorter than 3.
     */
    private static Set<String> subjectKeywords(String text, int valueStart) {
        int from = Math.max(0, valueStart - 60);
        String preamble = text.substring(from, valueStart);
        String compact = preamble.replaceAll("[^A-Za-z ]", " ")
                .replaceAll("\\s+", " ")
                .trim()
                .toLowerCase();
        if (compact.isEmpty()) return new HashSet<>();
        Set<String> kept = new HashSet<>();
        for (String w : compact.split(" ")) {
            if (w.length() < 3) continue;
            if (STOPWORDS.contains(w)) continue;
            kept.add(w);
        }
        return kept;
    }

    /** Trust ranking when picking which passage represents a value. */
    private static final List<String> TRUST_ORDER = Arrays.asList(
            "VENDOR_MANUAL", "DATASHEET", "ACADEMIC", "CODE", "FORUM", "UNKNOWN"
    );

    private static Observation pickRepresentative(List<Observation> observations) {
        Observation best = observations.get(0);
        int bestRank = rankOf(best.passage.sourceType());
        for (int i = 1; i < observations.size(); i++) {
            Observation o = observations.get(i);
            int r = rankOf(o.passage.sourceType());
            if (r < bestRank) {
                best = o;
                bestRank = r;
            }
        }
        return best;
    }

    private static int rankOf(String type) {
        int idx = TRUST_ORDER.indexOf(type == null ? "UNKNOWN" : type);
        return idx < 0 ? TRUST_ORDER.size() : idx;
    }

    /** Tiny English stopwords; enough to keep subject buckets tight. */
    private static final Set<String> STOPWORDS = new HashSet<>(Arrays.asList(
            "the", "and", "are", "for", "with", "this", "that", "from",
            "into", "onto", "over", "under", "when", "then", "than",
            "was", "were", "has", "have", "had", "can", "its", "our",
            "your", "you", "they", "them", "their", "his", "her", "its",
            "any", "all", "one", "two", "use", "used", "uses", "using",
            "some", "also", "still", "even", "ever", "just", "like",
            "but", "not", "too", "now", "here", "there", "these", "those",
            "which", "while", "where", "what", "how", "why", "via"
    ));

    /**
     * Light normalisation for value equality: strip quotes, lowercase,
     * collapse whitespace. Port "23" and "23 " compare equal; CVE
     * casing differences compare equal.
     */
    private static String normalise(String raw) {
        if (raw == null) return "";
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) return "";
        return trimmed
                .replace("\"", "")
                .replace("'", "")
                .replaceAll("\\s+", " ")
                .toLowerCase();
    }

    // Silence the unused-import warning in environments that strip
    // the LinkedHashMap / HashMap / Objects references at strip time.
    @SuppressWarnings("unused")
    private static void touch() {
        new HashMap<String, String>();
        Objects.requireNonNull(new LinkedHashMap<>());
    }
}

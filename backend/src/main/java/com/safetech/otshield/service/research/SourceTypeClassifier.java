package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.ResearchDocument.SourceType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Cheap heuristic classifier that stamps a {@link SourceType} on every
 * ingested document so the citation pill can show "Vendor Manual" vs
 * "Forum" at a glance, and a future cross-check service can detect
 * contradictions across high-trust / low-trust sources.
 *
 * <p>We deliberately don't run the LLM here:
 * <ul>
 *   <li>Ingest already takes tens of seconds for a PDF and researchers
 *       pipe multi-doc bundles in at once - an extra LLM roundtrip
 *       would make the Library feel broken.</li>
 *   <li>The five classes are coarse enough that filename + a small
 *       text sample nails them ~90% of the time. Users can override
 *       the rare misses from the Library row.</li>
 * </ul>
 *
 * <p>The classifier is strictly best-effort: on ambiguous or missing
 * input we return {@link SourceType#UNKNOWN}. Callers always get a
 * non-null enum so the DTO / column can be NOT NULL in principle even
 * though the schema keeps it nullable for migration comfort.
 */
@Component
@Slf4j
public class SourceTypeClassifier {

    /**
     * Extensions that immediately tell us we're looking at source code
     * or a configuration file. The vendor manual / datasheet split
     * still runs on extension-less or .pdf inputs below.
     */
    private static final List<String> CODE_EXTENSIONS = List.of(
            ".c", ".h", ".cpp", ".hpp", ".cc", ".py", ".js", ".ts",
            ".java", ".rs", ".go", ".rb", ".php", ".sh", ".bat",
            ".ps1", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
            ".json", ".xml", ".bin", ".hex", ".asm", ".s", ".lua"
    );

    /**
     * Heuristics keyed by {@link SourceType}. Each regex is run against
     * the concatenated {@code filename + " | " + head-sample} so a
     * match either on the filename OR on the first chunk of text wins.
     * The order matters: we prefer the narrowest class (DATASHEET
     * beats VENDOR_MANUAL) when both match, so VENDOR_MANUAL patterns
     * are checked last.
     */
    /**
     * A small "whitespace-or-punctuation" fragment we reuse in place of
     * plain {@code \s*} so filenames like {@code s7-1200-operator-manual.pdf}
     * still match the "operator manual" rule. Covers space, tab, dash,
     * underscore, dot and slash.
     */
    private static final String SEP = "[\\s\\-_./]*";

    private static final Map<SourceType, List<Pattern>> RULES = Map.of(
            SourceType.DATASHEET, List.of(
                    compile("(?:datasheet|data" + SEP + "sheet|spec" + SEP + "sheet|product" + SEP + "brief|technical" + SEP + "specifications?)"),
                    compile("(?:register" + SEP + "map|pinout|electrical" + SEP + "characteristics|absolute" + SEP + "maximum" + SEP + "ratings)")
            ),
            SourceType.ACADEMIC, List.of(
                    compile("\\b(?:abstract|keywords|references|bibliography|doi" + SEP + ":)\\b", true),
                    compile("\\barxiv(?::|\\.)\\b"),
                    compile("\\b(?:IEEE|ACM|Springer|Elsevier|USENIX|Black" + SEP + "Hat|DEFCON)\\b"),
                    compile("\\b(?:proceedings|conference|journal|thesis|dissertation|peer[-\\s]?reviewed)\\b")
            ),
            SourceType.FORUM, List.of(
                    compile("(?:forum|reddit|stack" + SEP + "(?:overflow|exchange)|mailing" + SEP + "list|discourse|github" + SEP + "issue|pastebin)"),
                    compile("(?:posted" + SEP + "by|user" + SEP + "said|re:|fwd:|thread" + SEP + "#)"),
                    compile("(?:hackaday|plctalk|automation" + SEP + "forum)")
            ),
            SourceType.VENDOR_MANUAL, List.of(
                    compile("(?:user" + SEP + "manual|operator(?:'s)?" + SEP + "manual|installation" + SEP + "manual|service" + SEP + "manual|maintenance" + SEP + "manual|programming" + SEP + "manual|reference" + SEP + "manual|hardware" + SEP + "guide|user" + SEP + "guide|owner(?:'s)?" + SEP + "manual)"),
                    // No word-boundary anchors here: filenames like
                    // "SIEMENS_LOGO.pdf" read as a single \w+ token
                    // under Java / JS regex, so \b fails to match. We
                    // just case-insensitively find the vendor name
                    // anywhere in the filename or text sample.
                    compile("(?:siemens|rockwell|allen[-\\s]?bradley|schneider|mitsubishi|omron|abb|honeywell|emerson|yokogawa|beckhoff|phoenix" + SEP + "contact|moxa)")
            )
    );

    /**
     * Classify a single document. Filename is always provided; the text
     * sample can be {@code null} for documents that haven't been
     * extracted yet (the enum still lands on {@link SourceType#UNKNOWN}
     * in that case and a re-classification will run after ingest).
     *
     * @param filename the uploaded file name, including extension.
     * @param textSample the first ~2 KB of extracted text. May be null
     *                   or empty; only the filename is inspected then.
     * @return the most specific match, or {@link SourceType#UNKNOWN}.
     */
    public SourceType classify(String filename, String textSample) {
        String name = filename == null ? "" : filename.toLowerCase();

        // Extension shortcut for source code - no regex work needed.
        for (String ext : CODE_EXTENSIONS) {
            if (name.endsWith(ext)) {
                log.debug("Classifier: '{}' matched CODE via extension {}", filename, ext);
                return SourceType.CODE;
            }
        }

        String sample = textSample == null ? "" : textSample;
        if (sample.length() > 2048) sample = sample.substring(0, 2048);
        String haystack = (name + " | " + sample).toLowerCase();

        // Check narrowest classes first; fall back to VENDOR_MANUAL; if
        // nothing matches, return UNKNOWN so the UI flags the doc for
        // manual classification.
        for (SourceType candidate : List.of(SourceType.DATASHEET, SourceType.ACADEMIC,
                                            SourceType.FORUM, SourceType.VENDOR_MANUAL)) {
            for (Pattern p : RULES.getOrDefault(candidate, List.of())) {
                if (p.matcher(haystack).find()) {
                    log.debug("Classifier: '{}' matched {} via /{}/",
                            filename, candidate, p.pattern());
                    return candidate;
                }
            }
        }
        return SourceType.UNKNOWN;
    }

    private static Pattern compile(String regex) {
        return compile(regex, false);
    }

    private static Pattern compile(String regex, boolean multiline) {
        int flags = Pattern.CASE_INSENSITIVE;
        if (multiline) flags |= Pattern.MULTILINE;
        return Pattern.compile(regex, flags);
    }
}

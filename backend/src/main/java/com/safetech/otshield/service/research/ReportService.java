package com.safetech.otshield.service.research;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.BundleSummary;
import com.safetech.otshield.model.research.ResearchBundle;
import com.safetech.otshield.model.research.ResearchFinding;
import com.safetech.otshield.model.research.ResearchMessage;
import com.safetech.otshield.model.research.ResearchThread;
import com.safetech.otshield.model.research.VulnObservation;
import com.safetech.otshield.service.assistant.SourceCrossCheckService.ConsistencyWarning;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Renders a tear-down research report as a single PDF the analyst can
 * hand to a reviewer. The report is deliberately linear — cover,
 * executive summary, findings ledger, vulnerability observations,
 * thread transcripts (with citations and consistency warnings) — so a
 * PDF reader with no interactive chrome is enough to read the whole
 * investigation end-to-end.
 *
 * <p>Rendering strategy is plain PDFBox: fixed-width body pages,
 * naive word wrap, simple heading / body style split. No templates,
 * no fancy layout engine; this keeps the output portable (no embedded
 * fonts beyond Helvetica) and the class small enough to audit by eye.
 *
 * <p>All per-bundle look-ups are filtered by {@code bundleId}. When
 * the caller asks for a bundle that doesn't exist we still return a
 * minimal PDF ("Bundle not found") rather than throwing - the report
 * endpoint always needs to resolve to bytes, even on the cold path.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ReportService {

    private final BundleService bundleService;
    private final SummaryService summaryService;
    private final FindingService findingService;
    private final VulnService vulnService;
    private final ThreadService threadService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ----- page geometry -----
    private static final float MARGIN_X = 56f;          // ~0.78 in
    private static final float MARGIN_TOP = 56f;
    private static final float MARGIN_BOTTOM = 56f;
    private static final float BODY_FONT_SIZE = 10.5f;
    private static final float BODY_LEADING = 14.5f;    // line height
    private static final float H1_FONT_SIZE = 20f;
    private static final float H2_FONT_SIZE = 14f;
    private static final float SMALL_FONT_SIZE = 9f;

    /**
     * Build the PDF for one bundle. Always returns bytes; on any
     * unexpected IOException we log and throw a {@link RuntimeException}
     * so the controller can 500. Missing data is rendered as
     * "(not available)" rather than absent so the reader sees the
     * full skeleton even on a fresh bundle.
     */
    public byte[] buildBundleReport(String bundleId) {
        Optional<ResearchBundle> bundleOpt = bundleService.get(bundleId);
        ResearchBundle bundle = bundleOpt.orElse(null);

        BundleSummary summary = bundle == null ? null
                : summaryService.get(bundleId).orElse(null);
        List<ResearchFinding> findings = bundle == null
                ? Collections.emptyList()
                : findingService.listFindings(bundleId);
        List<VulnObservation> vulns = bundle == null
                ? Collections.emptyList()
                : vulnService.list(bundleId);
        List<ResearchThread> threads = bundle == null
                ? Collections.emptyList()
                : threadService.listThreads(bundleId);

        try (PDDocument doc = new PDDocument();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            PageWriter writer = new PageWriter(doc);
            writer.beginPage();

            // ----- cover -----
            writer.writeHeading(bundle == null ? "Research Report" : bundle.getName(), H1_FONT_SIZE);
            writer.writeSubtitle(bundle == null
                    ? "Bundle not found"
                    : "Tear-down research report · generated "
                        + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
            if (bundle != null && bundle.getDescription() != null && !bundle.getDescription().isBlank()) {
                writer.spacer(6);
                writer.writeParagraph(bundle.getDescription());
            }
            writer.spacer(14);
            writer.writeKpiRow(new String[] {
                    "Findings", String.valueOf(findings.size()),
                    "Vulnerabilities", String.valueOf(vulns.size()),
                    "Threads", String.valueOf(threads.size())
            });

            // ----- summary -----
            writer.spacer(18);
            writer.writeHeading("Executive summary", H2_FONT_SIZE);
            if (summary == null || summary.getText() == null || summary.getText().isBlank()) {
                writer.writeMuted("(no summary generated for this bundle)");
            } else {
                writer.writeParagraph(summary.getText());
            }

            // ----- findings -----
            writer.spacer(18);
            writer.writeHeading("Findings · " + findings.size(), H2_FONT_SIZE);
            if (findings.isEmpty()) {
                writer.writeMuted("(no findings promoted)");
            } else {
                int n = 1;
                for (ResearchFinding f : findings) {
                    writer.writeBullet(n + ". " + safe(f.getTitle()));
                    if (f.getTags() != null && !f.getTags().isBlank()) {
                        writer.writeMuted("   tags: " + f.getTags());
                    }
                    writer.writeParagraph(indent(safe(f.getText()), 3));
                    writer.spacer(6);
                    n++;
                }
            }

            // ----- vulns -----
            writer.spacer(10);
            writer.writeHeading("Vulnerability observations · " + vulns.size(), H2_FONT_SIZE);
            if (vulns.isEmpty()) {
                writer.writeMuted("(no vulnerability observations)");
            } else {
                int n = 1;
                for (VulnObservation v : vulns) {
                    String head = n + ". " + safe(v.getTitle())
                            + "  ["
                            + (v.getSeverity() == null ? "?" : v.getSeverity().name())
                            + " · "
                            + (v.getConfidence() == null ? "?" : v.getConfidence().name())
                            + " · "
                            + (v.getStatus() == null ? "?" : v.getStatus().name())
                            + "]";
                    writer.writeBullet(head);
                    if (v.getComponentRef() != null && !v.getComponentRef().isBlank()) {
                        writer.writeMuted("   on: " + v.getComponentRef());
                    }
                    if (v.getSummary() != null && !v.getSummary().isBlank()) {
                        writer.writeParagraph(indent(v.getSummary(), 3));
                    }
                    writer.spacer(6);
                    n++;
                }
            }

            // ----- threads + transcripts -----
            writer.spacer(10);
            writer.writeHeading("Research threads · " + threads.size(), H2_FONT_SIZE);
            if (threads.isEmpty()) {
                writer.writeMuted("(no threads)");
            } else {
                for (ResearchThread t : threads) {
                    writer.writeBullet("· " + safe(t.getTitle()));
                    List<ResearchMessage> turns = threadService.listMessages(t.getId());
                    if (turns.isEmpty()) {
                        writer.writeMuted("   (empty thread)");
                        continue;
                    }
                    for (ResearchMessage m : turns) {
                        String tag = "user".equalsIgnoreCase(m.getRole()) ? "Q:" : "A:";
                        writer.writeParagraph(indent(tag + " " + safe(m.getContent()), 3));
                        if ("assistant".equalsIgnoreCase(m.getRole())) {
                            String confLabel = m.getConfidence() == null ? "—" : m.getConfidence();
                            String nmsLabel = m.getNeedsMoreSources() == null
                                    ? ""
                                    : (m.getNeedsMoreSources() ? " · needs more sources" : "");
                            writer.writeMuted("      confidence: " + confLabel + nmsLabel);

                            List<?> citations = threadService.parseCitations(m.getCitationsJson());
                            if (!citations.isEmpty()) {
                                writer.writeMuted("      sources: " + citations.size());
                            }

                            List<ConsistencyWarning> warnings = parseConsistency(m.getConsistencyJson());
                            if (!warnings.isEmpty()) {
                                writer.writeMuted("      ⚠ " + warnings.size()
                                        + " source consistency warning"
                                        + (warnings.size() == 1 ? "" : "s"));
                            }
                        }
                        writer.spacer(3);
                    }
                    writer.spacer(8);
                }
            }

            // ----- footer on every page -----
            writer.finishDocument();
            doc.save(out);
            return out.toByteArray();
        } catch (IOException e) {
            log.error("Report render failed for bundle {}: {}", bundleId, e.getMessage(), e);
            throw new RuntimeException("Could not render PDF report: " + e.getMessage(), e);
        }
    }

    private List<ConsistencyWarning> parseConsistency(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return objectMapper.readerForListOf(ConsistencyWarning.class).readValue(json);
        } catch (Exception e) {
            log.debug("Report: could not parse consistency JSON: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    private static String safe(String s) {
        if (s == null) return "";
        // PDFBox WinAnsi encoding chokes on non-latin1 characters; the
        // simplest fix is to strip anything out of range. We keep
        // basic whitespace and ASCII punctuation.
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') continue;
            if (c > 0xFF) {
                // Transliterate a handful of common non-ASCII punctuation
                // into ASCII approximations so the PDF doesn't get holes.
                switch (c) {
                    case '\u2013', '\u2014' -> sb.append('-');
                    case '\u2018', '\u2019' -> sb.append('\'');
                    case '\u201C', '\u201D' -> sb.append('"');
                    case '\u2026' -> sb.append("...");
                    default -> sb.append('?');
                }
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static String indent(String s, int spaces) {
        if (s == null) return "";
        String pad = " ".repeat(spaces);
        return pad + s.replace("\n", "\n" + pad);
    }

    // ------------------------------------------------------------------
    // PageWriter — tiny helper that abstracts "current page + cursor"
    // so the report-building code stays linear.
    // ------------------------------------------------------------------

    /**
     * Thin stateful wrapper over a PDDocument that knows how to start
     * new pages, wrap lines, and emit our three block kinds (heading,
     * paragraph, muted note). Intentionally not a Spring bean - one
     * instance per report so there's no shared mutable state.
     */
    private static final class PageWriter {

        private final PDDocument doc;
        private PDPage page;
        private PDPageContentStream cs;
        private float y;
        private int pageNumber = 0;

        PageWriter(PDDocument doc) {
            this.doc = doc;
        }

        void beginPage() throws IOException {
            if (cs != null) {
                drawFooter();
                cs.close();
            }
            page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            pageNumber++;
            cs = new PDPageContentStream(doc, page);
            y = page.getMediaBox().getHeight() - MARGIN_TOP;
        }

        void finishDocument() throws IOException {
            if (cs != null) {
                drawFooter();
                cs.close();
                cs = null;
            }
        }

        private void drawFooter() throws IOException {
            float footerY = MARGIN_BOTTOM / 2;
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), SMALL_FONT_SIZE);
            cs.setNonStrokingColor(128, 128, 128);
            cs.beginText();
            cs.newLineAtOffset(MARGIN_X, footerY);
            cs.showText("OTShield Research Studio · page " + pageNumber);
            cs.endText();
            cs.setNonStrokingColor(0, 0, 0);
        }

        private void ensureSpaceFor(float needed) throws IOException {
            if (y - needed < MARGIN_BOTTOM) beginPage();
        }

        // ----- block primitives -----

        void writeHeading(String text, float size) throws IOException {
            ensureSpaceFor(size + 10);
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), size);
            cs.beginText();
            cs.newLineAtOffset(MARGIN_X, y);
            cs.showText(safeOneLine(text));
            cs.endText();
            y -= size + 6;
        }

        void writeSubtitle(String text) throws IOException {
            ensureSpaceFor(BODY_FONT_SIZE + 4);
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_OBLIQUE), BODY_FONT_SIZE);
            cs.setNonStrokingColor(110, 110, 110);
            cs.beginText();
            cs.newLineAtOffset(MARGIN_X, y);
            cs.showText(safeOneLine(text));
            cs.endText();
            cs.setNonStrokingColor(0, 0, 0);
            y -= BODY_LEADING;
        }

        void writeParagraph(String text) throws IOException {
            if (text == null || text.isBlank()) return;
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), BODY_FONT_SIZE);
            float maxWidth = page.getMediaBox().getWidth() - 2 * MARGIN_X;
            for (String paragraph : text.split("\\r?\\n")) {
                List<String> wrapped = wrap(paragraph, maxWidth, BODY_FONT_SIZE, false);
                for (String line : wrapped) {
                    ensureSpaceFor(BODY_LEADING);
                    cs.beginText();
                    cs.newLineAtOffset(MARGIN_X, y);
                    cs.showText(line);
                    cs.endText();
                    y -= BODY_LEADING;
                }
            }
        }

        void writeBullet(String text) throws IOException {
            if (text == null || text.isBlank()) return;
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), BODY_FONT_SIZE);
            ensureSpaceFor(BODY_LEADING);
            cs.beginText();
            cs.newLineAtOffset(MARGIN_X, y);
            cs.showText(safeOneLine(text));
            cs.endText();
            y -= BODY_LEADING;
        }

        void writeMuted(String text) throws IOException {
            if (text == null || text.isBlank()) return;
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), SMALL_FONT_SIZE);
            cs.setNonStrokingColor(110, 110, 110);
            ensureSpaceFor(BODY_LEADING);
            cs.beginText();
            cs.newLineAtOffset(MARGIN_X, y);
            cs.showText(safeOneLine(text));
            cs.endText();
            cs.setNonStrokingColor(0, 0, 0);
            y -= BODY_LEADING;
        }

        void writeKpiRow(String[] pairs) throws IOException {
            // Render as "Label: value · Label: value · ..." on one line.
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < pairs.length; i += 2) {
                if (i + 1 >= pairs.length) break;
                if (sb.length() > 0) sb.append("    \u2022    ".replace("\u2022", "•"));
                sb.append(pairs[i]).append(": ").append(pairs[i + 1]);
            }
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), BODY_FONT_SIZE);
            cs.setNonStrokingColor(80, 60, 180);
            ensureSpaceFor(BODY_LEADING);
            cs.beginText();
            cs.newLineAtOffset(MARGIN_X, y);
            cs.showText(safeOneLine(sb.toString()));
            cs.endText();
            cs.setNonStrokingColor(0, 0, 0);
            y -= BODY_LEADING;
        }

        void spacer(float px) throws IOException {
            y -= px;
            if (y < MARGIN_BOTTOM) beginPage();
        }

        // ----- wrapping -----

        private List<String> wrap(String text, float maxWidth, float fontSize, boolean bold) throws IOException {
            List<String> out = new ArrayList<>();
            if (text == null) return out;
            String cleaned = safeOneLine(text);
            if (cleaned.isBlank()) {
                out.add("");
                return out;
            }
            PDType1Font font = new PDType1Font(
                    bold ? Standard14Fonts.FontName.HELVETICA_BOLD : Standard14Fonts.FontName.HELVETICA);
            String[] words = cleaned.split(" ");
            StringBuilder line = new StringBuilder();
            for (String w : words) {
                String candidate = line.length() == 0 ? w : line + " " + w;
                float width = font.getStringWidth(candidate) / 1000f * fontSize;
                if (width > maxWidth && line.length() > 0) {
                    out.add(line.toString());
                    line = new StringBuilder(w);
                } else {
                    if (line.length() > 0) line.append(' ');
                    line.append(w);
                }
            }
            if (line.length() > 0) out.add(line.toString());
            return out;
        }

        /** Strip control chars + replace non-latin1 with ASCII approx. */
        private static String safeOneLine(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '\n' || c == '\r' || c == '\t') { sb.append(' '); continue; }
                if (c < 0x20) continue;
                if (c > 0xFF) {
                    switch (c) {
                        case '\u2013', '\u2014' -> sb.append('-');
                        case '\u2018', '\u2019' -> sb.append('\'');
                        case '\u201C', '\u201D' -> sb.append('"');
                        case '\u2026' -> sb.append("...");
                        case '\u2022' -> sb.append("*");
                        case '\u26A0' -> sb.append("!");
                        default -> sb.append('?');
                    }
                    continue;
                }
                sb.append(c);
            }
            return sb.toString();
        }
    }
}

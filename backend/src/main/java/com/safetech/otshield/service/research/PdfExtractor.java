package com.safetech.otshield.service.research;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Lifts text out of a PDF one page at a time, preserving the page number
 * alongside the text so chunks we build downstream can cite the exact
 * source location. We lean on Apache PDFBox 3 because it's pure-Java,
 * offline-friendly, and handles the vast majority of machine manuals
 * and datasheets without any special configuration.
 *
 * <p>This extractor intentionally ignores images, annotations, and form
 * fields. Those will come in Faz 3.1 when we layer a VLM on top for
 * schematic understanding. For now the goal is "get the narrative text
 * and any table text PDFBox can reach" - good enough for the HMGCC
 * tear-down use case's vendor-manual-as-PDF scenario.
 */
@Component
@Slf4j
public class PdfExtractor {

    /** One slice of extracted text tied to a specific page number. */
    public record ExtractedPage(int pageNumber, String text) {}

    /**
     * Extract text page-by-page. Empty pages (cover art, blank leaves)
     * are dropped so they don't generate zero-length chunks. If the PDF
     * cannot be loaded at all we throw - the caller flips the document
     * to FAILED and surfaces the message in the Library UI.
     */
    public List<ExtractedPage> extract(File pdfFile) {
        List<ExtractedPage> pages = new ArrayList<>();
        try (PDDocument doc = Loader.loadPDF(pdfFile)) {
            int total = doc.getNumberOfPages();
            PDFTextStripper stripper = new PDFTextStripper();
            // PDFBox is 1-based for start/end page.
            for (int p = 1; p <= total; p++) {
                stripper.setStartPage(p);
                stripper.setEndPage(p);
                String raw = stripper.getText(doc);
                String cleaned = cleanupPageText(raw);
                if (!cleaned.isBlank()) {
                    pages.add(new ExtractedPage(p, cleaned));
                }
            }
            log.info("Extracted {} non-empty pages from '{}'", pages.size(), pdfFile.getName());
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract PDF text from " + pdfFile.getName(), e);
        }
        return pages;
    }

    /**
     * Returns the raw page count of the PDF - stored on the document row
     * even if some pages are blank and excluded from the chunk stream.
     */
    public int countPages(File pdfFile) {
        try (PDDocument doc = Loader.loadPDF(pdfFile)) {
            return doc.getNumberOfPages();
        } catch (Exception e) {
            log.warn("Could not count pages of {}: {}", pdfFile.getName(), e.getMessage());
            return 0;
        }
    }

    /**
     * PDF extraction routinely produces ugly whitespace: stray line
     * breaks mid-sentence from column wraps, hyphenated word splits,
     * multiple spaces. We don't try to be perfect - just normalise
     * enough that the embedder sees sentence-shaped input.
     */
    private String cleanupPageText(String raw) {
        if (raw == null) return "";
        // Rejoin hyphenated line breaks: "manu-\nfacturer" -> "manufacturer".
        String s = raw.replaceAll("(\\w)-\\n(\\w)", "$1$2");
        // Single newline inside a paragraph -> space; double newlines preserve paragraph breaks.
        s = s.replaceAll("(?<!\\n)\\n(?!\\n)", " ");
        // Collapse runs of whitespace.
        s = s.replaceAll("[ \\t]+", " ");
        // Trim paragraph edges.
        s = s.replaceAll("(?m)^[ \\t]+|[ \\t]+$", "");
        return s.trim();
    }
}

package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.ResearchBundle;
import com.safetech.otshield.repository.research.ResearchBundleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.*;
import java.util.stream.Stream;

/**
 * Background scanner that watches each bundle's {@code watchFolderPath}
 * for new files and feeds them into the Library.
 *
 * <p>Why this exists: HMGCC's "must work without an internet
 * connection" constraint means researchers move files between
 * machines via sneakernet or a shared drop folder. Rather than make
 * them click "Upload" in the UI every time, a bundle can point at a
 * server-side folder and let this poller pick up anything new.
 *
 * <p>Design:
 *
 * <ul>
 *   <li>Runs on Spring's scheduler every 30 seconds by default. The
 *       interval is fixed at compile time - users don't need to tune
 *       it and tying it to a property leaves a foot-gun.</li>
 *   <li>Only bundles with {@code watch_enabled = true} and a
 *       non-blank {@code watch_folder_path} are scanned.</li>
 *   <li>Picked-up files are copied into managed storage (the normal
 *       ingest path) and then moved into a
 *       {@code .otshield-processed/} subfolder of the watch directory
 *       so the same file doesn't re-ingest on the next tick. The
 *       "move" step is idempotent; if another process is still
 *       writing the file, the poller sees {@code NoSuchFileException}
 *       and tries again next tick.</li>
 *   <li>Errors are swallowed at the bundle boundary - one bad folder
 *       must not stop the other bundles' pollers.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WatchFolderPoller {

    private static final String PROCESSED_SUBDIR = ".otshield-processed";

    private final ResearchBundleRepository bundleRepo;
    private final ResearchIngestService ingestService;

    /**
     * Poll every 30 seconds. Initial delay is 20s so watch folders
     * don't fight with the startup seeder + RAG rehydrate for CPU.
     */
    @Scheduled(fixedDelay = 30_000, initialDelay = 20_000)
    public void tick() {
        for (ResearchBundle bundle : bundleRepo.findAll()) {
            if (!bundle.isWatchEnabled()) continue;
            String path = bundle.getWatchFolderPath();
            if (path == null || path.isBlank()) continue;

            try {
                processBundle(bundle, Paths.get(path));
            } catch (Exception e) {
                log.warn("Watch poller: bundle={} error: {}", bundle.getId(), e.getMessage());
            }
        }
    }

    private void processBundle(ResearchBundle bundle, Path dir) throws IOException {
        if (!Files.isDirectory(dir)) {
            log.debug("Watch poller: bundle={} folder does not exist: {}", bundle.getId(), dir);
            return;
        }
        Path processedDir = dir.resolve(PROCESSED_SUBDIR);
        if (!Files.isDirectory(processedDir)) {
            Files.createDirectories(processedDir);
        }

        try (Stream<Path> stream = Files.list(dir)) {
            stream
                .filter(Files::isRegularFile)
                .filter(p -> !p.getFileName().toString().startsWith(".")) // skip hidden / temp
                .forEach(p -> ingestOne(bundle, p, processedDir));
        }
    }

    /**
     * Copy one file into the library for this bundle and then move
     * the source into {@code .otshield-processed/}. Failures leave
     * the source file in place so the next tick retries; the copy
     * step into storage is the risky one and runs inside the ingest
     * service's own error handling.
     */
    private void ingestOne(ResearchBundle bundle, Path file, Path processedDir) {
        String name = file.getFileName().toString();
        try {
            ingestService.ingestFromPath(file, null, bundle.getId());
            log.info("Watch poller: bundle={} ingested '{}'", bundle.getId(), name);

            // Move out of the way so we don't re-ingest on the next tick.
            Path target = uniqueInside(processedDir, name);
            Files.move(file, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (NoSuchFileException nsfe) {
            // Either another process raced us or the file was still
            // being written. Either way, we'll see it (or not) next
            // tick - nothing to do here.
            log.debug("Watch poller: bundle={} file vanished mid-ingest: {}", bundle.getId(), name);
        } catch (Exception e) {
            log.warn("Watch poller: bundle={} could not ingest '{}': {}",
                    bundle.getId(), name, e.getMessage());
        }
    }

    /**
     * Avoid collisions inside the processed folder: if a file with
     * the same name already exists, tack on a numeric suffix.
     */
    private Path uniqueInside(Path dir, String name) {
        Path candidate = dir.resolve(name);
        if (!Files.exists(candidate)) return candidate;
        int n = 2;
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;
        String ext  = dot > 0 ? name.substring(dot)    : "";
        while (Files.exists(candidate) && n < 1000) {
            candidate = dir.resolve(base + "-" + n + ext);
            n++;
        }
        return candidate;
    }
}

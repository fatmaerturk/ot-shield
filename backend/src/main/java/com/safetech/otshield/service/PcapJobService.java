package com.safetech.otshield.service;

import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks asynchronous PCAP-analysis jobs so the upload endpoint can return
 * immediately and the UI can poll for progress.
 *
 * <p>A large capture is parsed with bounded (windowed) memory but still takes
 * minutes - an ~87 MB IEC-104 file yields ~573k DPI events over ~8 min. Holding
 * the HTTP request open that long just invites client timeouts (the misleading
 * "Could not connect to server"), so {@code FileController} now hands the parse
 * to this service and returns a {@code jobId}. The parse runs on a small bounded
 * pool (so N concurrent uploads can't each spin up an unbounded in-memory
 * parse), updating its {@link Job} as each window is persisted.
 *
 * <p>Job state is in-memory only: it's live progress for an in-flight upload,
 * not durable data. The real result - DPI events, assets, anomalies - is in the
 * database the moment each window is persisted, independent of this registry.
 */
@Service
public class PcapJobService {

    public enum State { PROCESSING, DONE, ERROR }

    /** Mutable, thread-safe snapshot of one upload's progress. */
    public static class Job {
        public final String jobId;
        public final String filename;
        public final long startedAt = System.currentTimeMillis();
        public volatile State state = State.PROCESSING;
        public volatile long packetsProcessed = 0;
        public volatile long total = 0;            // final full-file count once DONE
        public volatile String pcapSessionId;      // set as soon as parsing starts
        public volatile int newAssets = 0;
        public volatile int newAnomalies = 0;
        public volatile String error;              // set only on ERROR
        public volatile long finishedAt = 0;

        Job(String jobId, String filename) {
            this.jobId = jobId;
            this.filename = filename;
        }
    }

    /** Keep only the most recent jobs so the map can't grow without bound. */
    private static final int MAX_JOBS = 200;

    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(2, new ThreadFactory() {
        private final AtomicInteger n = new AtomicInteger(1);
        @Override public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "pcap-analysis-" + n.getAndIncrement());
            t.setDaemon(true);   // don't block JVM shutdown
            return t;
        }
    });

    /** Register a new job for {@code filename} and return its live handle. */
    public Job create(String filename) {
        Job job = new Job(UUID.randomUUID().toString(), filename);
        jobs.put(job.jobId, job);
        evictOldIfNeeded();
        return job;
    }

    /** Current snapshot for {@code jobId}, or {@code null} if unknown/evicted. */
    public Job get(String jobId) {
        return jobs.get(jobId);
    }

    /** Run the analysis task on the bounded background pool. */
    public void submit(Runnable task) {
        executor.submit(task);
    }

    private void evictOldIfNeeded() {
        if (jobs.size() <= MAX_JOBS) return;
        // Drop the oldest finished jobs first; never evict a still-running one.
        jobs.values().stream()
                .filter(j -> j.state != State.PROCESSING)
                .sorted((a, b) -> Long.compare(a.startedAt, b.startedAt))
                .limit(Math.max(0, jobs.size() - MAX_JOBS))
                .forEach(j -> jobs.remove(j.jobId));
    }

    @PreDestroy
    void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow();
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}

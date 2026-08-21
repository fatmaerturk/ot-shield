package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.TwinSpec;
import com.safetech.otshield.dto.cases.CreateCaseRequest;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.CaseCategory;
import com.safetech.otshield.model.CasePriority;
import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.repository.DpiEventRepository;
import com.safetech.otshield.service.AnomalyService;
import com.safetech.otshield.service.CaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * A MODBUS/TCP decoy digital twin - a real listener that impersonates a
 * discovered asset (its FC43 device identity + basic register behaviour) and
 * records every interaction. A write to the twin is a high-confidence signal:
 * nothing legitimate should ever touch it.
 *
 * SAFETY (this never puts the host at risk):
 *  - Binds ONLY to the loopback address (127.0.0.1); never 0.0.0.0, never a
 *    routable interface, so nothing off this machine can reach it.
 *  - Off by default - only runs when explicitly started, one twin at a time.
 *  - Defensive parser: bounded frame size, per-connection read timeout, a small
 *    fixed thread pool, and every connection wrapped in try/catch so malformed
 *    input can neither hang nor crash the app.
 */
@Component
public class ModbusTwinEmulator {

    private static final Logger log = LoggerFactory.getLogger(ModbusTwinEmulator.class);

    private static final int MAX_FRAME = 260;      // MODBUS/TCP max ADU
    private static final int READ_TIMEOUT_MS = 5000;
    private static final int MAX_INTERACTIONS = 500;

    private volatile ServerSocket serverSocket;
    private volatile Thread acceptThread;
    private volatile ExecutorService pool;
    private volatile TwinSpec active;

    private final Deque<Map<String, Object>> interactions = new ConcurrentLinkedDeque<>();
    // One asset-level case per (asset, attacker) while a twin runs - avoids spam.
    private final Set<String> casedKeys = ConcurrentHashMap.newKeySet();

    private final CaseService caseService;
    private final DpiEventRepository dpiRepo;
    private final AnomalyService anomalyService;

    // Behavioral clone: register address -> current value. Seeded from the real
    // device's observed values (DPI), then drifted over time so reads evolve like
    // a live process. Writes stick, so the twin behaves like a real PLC.
    private volatile Map<Integer, Integer> registerBaselines = new ConcurrentHashMap<>();
    private volatile int realIpHash;

    public ModbusTwinEmulator(CaseService caseService, DpiEventRepository dpiRepo, AnomalyService anomalyService) {
        this.caseService = caseService;
        this.dpiRepo = dpiRepo;
        this.anomalyService = anomalyService;
    }

    public static final class TwinResult {
        public final String host; public final int port;
        public TwinResult(String host, int port) { this.host = host; this.port = port; }
    }

    public synchronized boolean isRunning() { return serverSocket != null && !serverSocket.isClosed(); }

    public synchronized TwinSpec activeSpec() { return active; }

    public List<Map<String, Object>> recentInteractions() {
        return new ArrayList<>(interactions);
    }

    /** Start (or restart) the twin on a loopback ephemeral port. */
    public synchronized TwinResult start(TwinSpec spec) throws IOException {
        stop();
        casedKeys.clear();
        loadBehavior(spec);
        // Bind to loopback ONLY. This is the load-bearing safety control.
        ServerSocket ss = new ServerSocket();
        ss.bind(new java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 16);
        this.serverSocket = ss;
        this.pool = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "modbus-twin"); t.setDaemon(true); return t;
        });
        this.active = spec;
        spec.setListenHost(ss.getInetAddress().getHostAddress());
        spec.setListenPort(ss.getLocalPort());
        spec.setRunning(true);

        Thread accept = new Thread(() -> acceptLoop(ss, spec), "modbus-twin-accept");
        accept.setDaemon(true);
        accept.start();
        this.acceptThread = accept;

        log.info("Twin emulator for {} ({}) listening on {}:{}",
                spec.getModelName(), spec.getRealIp(), spec.getListenHost(), spec.getListenPort());
        return new TwinResult(spec.getListenHost(), ss.getLocalPort());
    }

    public synchronized void stop() {
        if (active != null) active.setRunning(false);
        ServerSocket ss = this.serverSocket;
        this.serverSocket = null;
        if (ss != null) try { ss.close(); } catch (IOException ignored) { }
        ExecutorService p = this.pool; this.pool = null;
        if (p != null) p.shutdownNow();
        this.acceptThread = null;
    }

    @PreDestroy
    public void shutdown() { stop(); }

    private void acceptLoop(ServerSocket ss, TwinSpec spec) {
        while (!ss.isClosed()) {
            final Socket client;
            try {
                client = ss.accept();
            } catch (IOException e) {
                break; // socket closed -> stop
            }
            ExecutorService p = this.pool;
            if (p == null) { try { client.close(); } catch (IOException ignored) { } break; }
            try {
                p.submit(() -> handle(client, spec));
            } catch (RejectedExecutionException rej) {
                try { client.close(); } catch (IOException ignored) { }
            }
        }
    }

    private void handle(Socket client, TwinSpec spec) {
        String remote = client.getInetAddress() != null ? client.getInetAddress().getHostAddress() : "?";
        try {
            client.setSoTimeout(READ_TIMEOUT_MS);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            byte[] mbap = new byte[7];
            while (true) {
                if (!readFully(in, mbap, 7)) break; // EOF
                int len = ((mbap[4] & 0xFF) << 8) | (mbap[5] & 0xFF);
                int pduLen = len - 1; // len counts unit(1) + PDU
                if (pduLen <= 0 || pduLen > MAX_FRAME) break; // malformed / oversized
                byte[] pdu = new byte[pduLen];
                if (!readFully(in, pdu, pduLen)) break;

                byte[] respPdu = buildResponse(pdu, spec, remote);
                byte[] frame = new byte[7 + respPdu.length];
                frame[0] = mbap[0]; frame[1] = mbap[1];       // transaction id echo
                frame[2] = 0; frame[3] = 0;                   // protocol id
                int rlen = respPdu.length + 1;
                frame[4] = (byte) ((rlen >> 8) & 0xFF); frame[5] = (byte) (rlen & 0xFF);
                frame[6] = mbap[6];                           // unit id echo
                System.arraycopy(respPdu, 0, frame, 7, respPdu.length);
                out.write(frame);
                out.flush();
            }
        } catch (Exception e) {
            // A single misbehaving client never affects the app.
        } finally {
            try { client.close(); } catch (IOException ignored) { }
        }
    }

    private byte[] buildResponse(byte[] pdu, TwinSpec spec, String remote) {
        int fc = pdu[0] & 0xFF;
        switch (fc) {
            case 0x2B: // Encapsulated Interface - Read Device Identification
                if (pdu.length >= 2 && (pdu[1] & 0xFF) == 0x0E) {
                    record(remote, fc, "Read Device Identification", false, "identity probe");
                    return deviceIdResponse(spec);
                }
                return exception(fc, 0x01);
            case 0x01: case 0x02: { // read coils / discrete inputs
                int addr = pdu.length >= 3 ? (((pdu[1] & 0xFF) << 8) | (pdu[2] & 0xFF)) : 0;
                int qty = pdu.length >= 5 ? (((pdu[3] & 0xFF) << 8) | (pdu[4] & 0xFF)) : 1;
                qty = Math.max(1, Math.min(qty, 2000));
                int bytes = (qty + 7) / 8;
                record(remote, fc, fcName(fc), false, "read " + qty + " @ " + addr);
                byte[] r = new byte[2 + bytes];
                r[0] = (byte) fc; r[1] = (byte) bytes;
                for (int i = 0; i < qty; i++) if ((regValue(addr + i) & 1) == 1) r[2 + i / 8] |= (1 << (i % 8));
                return r;
            }
            case 0x03: case 0x04: { // read holding / input registers -> evolving values
                int addr = pdu.length >= 3 ? (((pdu[1] & 0xFF) << 8) | (pdu[2] & 0xFF)) : 0;
                int qty = pdu.length >= 5 ? (((pdu[3] & 0xFF) << 8) | (pdu[4] & 0xFF)) : 1;
                qty = Math.max(1, Math.min(qty, 125));
                int bytes = qty * 2;
                record(remote, fc, fcName(fc), false, "read " + qty + " regs @ " + addr);
                byte[] r = new byte[2 + bytes];
                r[0] = (byte) fc; r[1] = (byte) bytes;
                for (int i = 0; i < qty; i++) {
                    int v = regValue(addr + i) & 0xFFFF;
                    r[2 + i * 2] = (byte) ((v >> 8) & 0xFF);
                    r[3 + i * 2] = (byte) (v & 0xFF);
                }
                return r;
            }
            case 0x05: case 0x06: // write single coil / register  -> HIGH SIGNAL
                if (fc == 0x06 && pdu.length >= 5) {                 // a write sticks, like a real PLC
                    registerBaselines.put(((pdu[1] & 0xFF) << 8) | (pdu[2] & 0xFF),
                                          ((pdu[3] & 0xFF) << 8) | (pdu[4] & 0xFF));
                }
                record(remote, fc, fcName(fc), true, "write to decoy");
                return Arrays.copyOf(pdu, Math.min(pdu.length, 5)); // echo request
            case 0x0F: case 0x10: { // write multiple  -> HIGH SIGNAL
                if (fc == 0x10 && pdu.length >= 6) {
                    int addr = ((pdu[1] & 0xFF) << 8) | (pdu[2] & 0xFF);
                    int qty = ((pdu[3] & 0xFF) << 8) | (pdu[4] & 0xFF);
                    int idx = 6;
                    for (int i = 0; i < qty && idx + 1 < pdu.length; i++, idx += 2)
                        registerBaselines.put(addr + i, ((pdu[idx] & 0xFF) << 8) | (pdu[idx + 1] & 0xFF));
                }
                record(remote, fc, fcName(fc), true, "write to decoy");
                byte[] r = new byte[5];
                r[0] = (byte) fc;
                for (int i = 1; i < 5 && i < pdu.length; i++) r[i] = pdu[i]; // echo addr+qty
                return r;
            }
            default:
                record(remote, fc, fcName(fc), false, "unsupported fc");
                return exception(fc, 0x01); // illegal function
        }
    }

    /** Build a MODBUS FC43/MEI 0x0E response carrying the cloned identity. */
    private byte[] deviceIdResponse(TwinSpec spec) {
        List<byte[]> objs = new ArrayList<>();
        objs.add(idObject(0x00, spec.getVendor()));
        objs.add(idObject(0x01, spec.getProductCode()));
        objs.add(idObject(0x05, spec.getModelName()));
        int total = 0; for (byte[] o : objs) total += o.length;
        byte[] r = new byte[7 + total];
        r[0] = 0x2B; r[1] = 0x0E; r[2] = 0x01; r[3] = (byte) 0x83; // fc, mei, code=basic, conformity
        r[4] = 0x00; r[5] = 0x00; r[6] = (byte) objs.size();       // more, next, numObjects
        int i = 7; for (byte[] o : objs) { System.arraycopy(o, 0, r, i, o.length); i += o.length; }
        return r;
    }

    private static byte[] idObject(int id, String value) {
        byte[] v = (value == null ? "" : value).getBytes(StandardCharsets.US_ASCII);
        if (v.length > 245) v = Arrays.copyOf(v, 245);
        byte[] o = new byte[2 + v.length];
        o[0] = (byte) id; o[1] = (byte) v.length;
        System.arraycopy(v, 0, o, 2, v.length);
        return o;
    }

    private static byte[] exception(int fc, int code) {
        return new byte[]{ (byte) (fc | 0x80), (byte) code };
    }

    // ---- Behavioral clone: register values learned from real traffic, drifting ----

    /** Seed the twin's registers from the real device's observed values (DPI). */
    private void loadBehavior(TwinSpec spec) {
        Map<Integer, Integer> base = new ConcurrentHashMap<>();
        this.realIpHash = spec.getRealIp() != null ? spec.getRealIp().hashCode() : 0;
        try {
            for (Object[] r : dpiRepo.registerProfile(spec.getRealIp(), PageRequest.of(0, 5000))) {
                Integer reg = parseIntSafe(r[0]);
                Integer val = parseIntSafe(r[1]);
                if (reg != null && val != null) base.putIfAbsent(reg, val & 0xFFFF);
            }
        } catch (Exception ignored) { }
        this.registerBaselines = base;
        log.info("Twin behavior: {} observed register(s) seeded for {}", base.size(), spec.getRealIp());
    }

    /**
     * Value for a register: the observed real value (or a stable per-device
     * pseudo-value) drifting slowly over time, so successive reads evolve like a
     * live process rather than reading a dead, all-zero device.
     */
    private int regValue(int addr) {
        Integer b = registerBaselines.get(addr);
        long base = (b != null) ? b : deterministicBaseline(addr);
        double t = System.currentTimeMillis() / 1000.0;
        double phase = ((addr * 0.137) % 1.0) * 2 * Math.PI;
        double amp = Math.max(2.0, base * 0.03);
        long v = Math.round(base + amp * Math.sin(2 * Math.PI * (t / 30.0) + phase));
        if (v < 0) v = 0;
        if (v > 65535) v = 65535;
        return (int) v;
    }

    /** A stable, plausible baseline for a register we never observed - seeded per device. */
    private long deterministicBaseline(int addr) {
        long h = ((long) realIpHash * 2654435761L) ^ ((long) addr * 40503L);
        return Math.abs(h) % 10000;
    }

    private static Integer parseIntSafe(Object o) {
        if (o == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("-?\\d+").matcher(o.toString());
        if (!m.find()) return null;
        try { return Integer.parseInt(m.group()); } catch (Exception e) { return null; }
    }

    private void record(String remote, int fc, String name, boolean write, String detail) {
        TwinSpec spec = this.active;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", Instant.now().toString());
        m.put("sourceIp", remote);
        m.put("functionCode", "0x" + String.format("%02X", fc));
        m.put("function", name);
        m.put("write", write);
        m.put("detail", detail);
        // Asset-level attribution: this interaction threatens the specific real
        // device the twin clones - not just "some MODBUS asset".
        if (spec != null) {
            m.put("threatensAssetId", spec.getAssetId());
            m.put("threatensAsset", spec.getAssetName());
            m.put("threatensIp", spec.getRealIp());
        }
        interactions.addFirst(m);
        while (interactions.size() > MAX_INTERACTIONS) interactions.pollLast();

        if (write && spec != null) {
            log.warn("Twin WRITE from {} fc=0x{} against twin of {} ({})",
                    remote, String.format("%02X", fc), spec.getAssetName(), spec.getRealIp());
            openAssetCase(spec, remote, fc, name);
        }
    }

    /** A write to the twin is hostile intent against a specific real asset - open a case naming it. */
    private void openAssetCase(TwinSpec spec, String remote, int fc, String fnName) {
        String key = spec.getAssetId() + "|" + remote;
        if (!casedKeys.add(key)) return; // already cased this attacker for this asset
        try {
            Set<String> tags = new LinkedHashSet<>();
            tags.add("twin");
            tags.add("decoy");
            tags.add("asset:" + spec.getAssetId());
            tags.add("ip:" + remote);
            tags.add("proto:" + (spec.getProtocol() == null ? "modbus" : spec.getProtocol().toLowerCase()));

            String description = "A write was issued against the decoy digital twin of "
                + spec.getAssetName() + " (" + spec.getRealIp() + ", "
                + spec.getVendor() + " " + spec.getModelName() + ").\n\n"
                + "Source: " + remote + "\n"
                + "Function: " + fnName + " (0x" + String.format("%02X", fc) + ")\n\n"
                + "The twin is a decoy - nothing legitimate ever writes to it, so this is a high-confidence signal of "
                + "hostile intent aimed at this specific device. Blast radius: this asset.";

            CreateCaseRequest req = CreateCaseRequest.builder()
                .title("Write against decoy twin of " + spec.getAssetName() + " (" + spec.getRealIp() + ")")
                .description(description)
                .priority(CasePriority.CRITICAL)
                .severity(AlertSeverity.HIGH)
                .category(CaseCategory.OT_DISRUPTION)
                .reporterName("OTShield Twin")
                .tags(tags)
                .build();
            caseService.create(req);
        } catch (Exception e) {
            log.warn("Twin case creation failed: {}", e.getMessage());
        }

        // A write to a decoy is also a detection signal - raise an anomaly. It is
        // false-positive-free: nothing legitimate ever writes to a twin.
        try {
            anomalyService.createAnomaly(AnomalyDTO.builder()
                .title("Write against decoy twin of " + spec.getAssetName() + " (" + spec.getRealIp() + ")")
                .description("A write hit the decoy digital twin of " + spec.getAssetName() + " (" + spec.getRealIp()
                    + ", " + spec.getVendor() + " " + spec.getModelName() + ") from " + remote
                    + ". No legitimate actor writes to a decoy, so this is a false-positive-free breach signal "
                    + "attributed to this specific device.")
                .anomalyType(Anomaly.AnomalyType.PROTOCOL_VIOLATION)
                .severity(Anomaly.AnomalySeverity.CRITICAL)
                .status(Anomaly.AnomalyStatus.DETECTED)
                .sourceIp(remote)
                .destinationIp(spec.getRealIp())
                .protocol(spec.getProtocol())
                .evidence("MODBUS " + fnName + " (0x" + String.format("%02X", fc) + ") from " + remote
                    + " against the decoy twin of " + spec.getRealIp() + ".")
                .mitigationSteps("Treat as a confirmed intrusion signal: isolate the source and review lateral movement toward the real device.")
                .recommendations("A twin trip requires no tuning - route these straight to the SOC as high-confidence incidents.")
                .confidenceScore(1.0)
                .riskScore(95.0)
                .mitreTactic("Impair Process Control")
                .mitreTechnique("Unauthorized Command Message")
                .mitreId("T0855")
                .indicators(new ArrayList<>(List.of("rule:decoy.twin_write", "decoy", "twin",
                    "asset:" + spec.getAssetId(), "source:" + remote)))
                .isActive(true)
                .createdBy("decoy-twin")
                .build());
        } catch (Exception e) {
            log.warn("Twin anomaly creation failed: {}", e.getMessage());
        }
    }

    private static String fcName(int fc) {
        switch (fc) {
            case 0x01: return "Read Coils";
            case 0x02: return "Read Discrete Inputs";
            case 0x03: return "Read Holding Registers";
            case 0x04: return "Read Input Registers";
            case 0x05: return "Write Single Coil";
            case 0x06: return "Write Single Register";
            case 0x0F: return "Write Multiple Coils";
            case 0x10: return "Write Multiple Registers";
            case 0x2B: return "Encapsulated Interface";
            default: return "Function 0x" + String.format("%02X", fc);
        }
    }

    private static boolean readFully(InputStream in, byte[] buf, int len) throws IOException {
        int off = 0;
        while (off < len) {
            int n = in.read(buf, off, len - off);
            if (n < 0) return false;
            off += n;
        }
        return true;
    }
}

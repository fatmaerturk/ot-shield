package com.safetech.otshield.repository;

import com.safetech.otshield.model.DpiEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Query API for {@link DpiEvent}. Typical access patterns:
 * <ul>
 *   <li>"last N events for a given src↔dst pair in a time window" - drives
 *       the Network Topology edge detail panel.</li>
 *   <li>"all events touching an IP" - drives the node detail panel.</li>
 *   <li>"function-code histogram" - drives the 'rare command' badge on the
 *       topology edge tooltip.</li>
 * </ul>
 */
@Repository
public interface DpiEventRepository extends JpaRepository<DpiEvent, String> {

    // --- Filtered searches --------------------------------------------------

    Page<DpiEvent> findBySourceIpAndDestinationIpOrderByEventTimeDesc(
            String sourceIp, String destinationIp, Pageable pageable);

    Page<DpiEvent> findByProtocolOrderByEventTimeDesc(String protocol, Pageable pageable);

    Page<DpiEvent> findByEventTimeBetweenOrderByEventTimeDesc(
            LocalDateTime start, LocalDateTime end, Pageable pageable);

    /**
     * Flexible filter - any parameter may be null to skip that clause. Ordered
     * by event_time desc so paging gives "most recent first".
     *
     * <p><b>Why the {@code CAST(... AS string/timestamp)} wrappers:</b> on
     * PostgreSQL, passing a raw {@code NULL} bind to both an {@code IS NULL}
     * test <i>and</i> a typed comparison in the same statement makes the
     * planner unable to infer the parameter's type, failing with
     * "could not determine data type of parameter $N". Casting makes the
     * expected SQL type explicit and lets PG plan the query correctly even
     * when the value is null.
     */
    @Query("""
            SELECT e FROM DpiEvent e WHERE
              (CAST(:sourceIp AS string) IS NULL OR e.sourceIp = :sourceIp) AND
              (CAST(:destinationIp AS string) IS NULL OR e.destinationIp = :destinationIp) AND
              (CAST(:ip AS string) IS NULL OR e.sourceIp = :ip OR e.destinationIp = :ip) AND
              (CAST(:protocol AS string) IS NULL OR e.protocol = :protocol) AND
              (CAST(:pduKind AS string) IS NULL OR e.pduKind = :pduKind) AND
              (CAST(:from AS timestamp) IS NULL OR e.eventTime >= :from) AND
              (CAST(:to AS timestamp) IS NULL OR e.eventTime <= :to)
            ORDER BY e.eventTime DESC
            """)
    Page<DpiEvent> search(
            @Param("sourceIp") String sourceIp,
            @Param("destinationIp") String destinationIp,
            @Param("ip") String ip,
            @Param("protocol") String protocol,
            @Param("pduKind") String pduKind,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            Pageable pageable
    );

    // --- Aggregations -------------------------------------------------------

    /**
     * Function-code histogram per (protocol, function_code) for a specific
     * src↔dst pair. Returns rows of [protocol, function_code, function_name, count].
     */
    @Query("""
            SELECT e.protocol, e.functionCode, e.functionName, COUNT(e)
            FROM DpiEvent e
            WHERE (CAST(:sourceIp AS string) IS NULL OR e.sourceIp = :sourceIp)
              AND (CAST(:destinationIp AS string) IS NULL OR e.destinationIp = :destinationIp)
              AND (CAST(:from AS timestamp) IS NULL OR e.eventTime >= :from)
              AND (CAST(:to AS timestamp) IS NULL OR e.eventTime <= :to)
              AND e.functionCode IS NOT NULL
            GROUP BY e.protocol, e.functionCode, e.functionName
            ORDER BY COUNT(e) DESC
            """)
    List<Object[]> functionCodeStats(
            @Param("sourceIp") String sourceIp,
            @Param("destinationIp") String destinationIp,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to
    );

    /**
     * Function-code histogram for every PDU touching a given IP (as source or
     * destination). Used when the user clicks a single node.
     */
    @Query("""
            SELECT e.protocol, e.functionCode, e.functionName, COUNT(e)
            FROM DpiEvent e
            WHERE (e.sourceIp = :ip OR e.destinationIp = :ip)
              AND (CAST(:from AS timestamp) IS NULL OR e.eventTime >= :from)
              AND (CAST(:to AS timestamp) IS NULL OR e.eventTime <= :to)
              AND e.functionCode IS NOT NULL
            GROUP BY e.protocol, e.functionCode, e.functionName
            ORDER BY COUNT(e) DESC
            """)
    List<Object[]> functionCodeStatsForNode(
            @Param("ip") String ip,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to
    );

    /**
     * Distinct src↔dst pairs with write activity in a window - feeds the
     * "suspicious writes" heuristic.
     */
    @Query("""
            SELECT e.sourceIp, e.destinationIp, e.protocol, COUNT(e)
            FROM DpiEvent e
            WHERE e.isWrite = true
              AND (CAST(:from AS timestamp) IS NULL OR e.eventTime >= :from)
              AND (CAST(:to AS timestamp) IS NULL OR e.eventTime <= :to)
            GROUP BY e.sourceIp, e.destinationIp, e.protocol
            ORDER BY COUNT(e) DESC
            """)
    List<Object[]> writeCommsSummary(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to
    );

    /**
     * Every distinct src↔dst pair ever observed in the DPI stream, with its
     * protocol and event count. Drives the Network Topology "observed
     * connections" edges - these are REAL links from the pcap dissector, not
     * anomaly-derived ones.
     *
     * Returns rows of [sourceIp, destinationIp, protocol, count].
     */
    @Query("""
            SELECT e.sourceIp, e.destinationIp, e.protocol, COUNT(e)
            FROM DpiEvent e
            WHERE e.sourceIp IS NOT NULL AND e.destinationIp IS NOT NULL
              AND (CAST(:from AS timestamp) IS NULL OR e.eventTime >= :from)
              AND (CAST(:to AS timestamp) IS NULL OR e.eventTime <= :to)
            GROUP BY e.sourceIp, e.destinationIp, e.protocol
            ORDER BY COUNT(e) DESC
            """)
    List<Object[]> observedConnections(
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to
    );

    /**
     * Global per-(protocol, functionCode) histogram <b>excluding</b> the given
     * pcap session. Used by the anomaly rule engine's "rare function code"
     * rule - we want to ask "is this fc rare against everything we've ever
     * seen <i>before</i> this upload?", which means excluding the just-saved
     * batch from the count.
     *
     * <p>Returns rows of [protocol, functionCode, count].
     */
    @Query("""
            SELECT e.protocol, e.functionCode, COUNT(e)
            FROM DpiEvent e
            WHERE e.functionCode IS NOT NULL
              AND (CAST(:excludeSession AS string) IS NULL OR e.pcapSessionId <> :excludeSession)
            GROUP BY e.protocol, e.functionCode
            """)
    List<Object[]> globalFunctionCodeHistogramExcludingSession(
            @Param("excludeSession") String excludeSession
    );

    // --- Session cleanup ---------------------------------------------------

    long countByPcapSessionId(String pcapSessionId);
    void deleteByPcapSessionId(String pcapSessionId);
}

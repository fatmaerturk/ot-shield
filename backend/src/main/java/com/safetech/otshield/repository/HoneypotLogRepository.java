package com.safetech.otshield.repository;

import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.dto.TtpLogRow;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface HoneypotLogRepository extends JpaRepository<HoneypotLog, Long> {

    /** Observed attack volume per protocol, e.g. [["MODBUS", 1705], ["FTP", 28417]].
     *  Used to weight asset risk by the real attack pressure on each OT protocol. */
    @Query("SELECT h.protocol, COUNT(h) FROM HoneypotLog h WHERE h.protocol IS NOT NULL GROUP BY h.protocol")
    List<Object[]> countByProtocol();

    /** Id-ordered tail of newly ingested hits, for real-time SIEM forwarding of
     *  internet-exposed decoy interactions (id is monotonic, immune to clock skew). */
    List<HoneypotLog> findTop500ByIdGreaterThanOrderByIdAsc(Long id);

    /** Highest id currently stored, used to skip the historical backlog when
     *  forwarding starts (only hits arriving afterwards are shipped). */
    HoneypotLog findTopByOrderByIdDesc();
    
    List<HoneypotLog> findAllByOrderByTimestampDesc();

    /** Bounded most-recent fetch for snapshot computations (e.g. NIS2 posture)
     *  so we don't hydrate the entire honeypot_logs table on every request. */
    List<HoneypotLog> findTop8000ByOrderByTimestampDesc();
    
    List<HoneypotLog> findBySourceIpOrderByTimestampDesc(String sourceIp);
    
    List<HoneypotLog> findByProtocolOrderByTimestampDesc(String protocol);
    
    List<HoneypotLog> findBySeverityOrderByTimestampDesc(String severity);
    
    List<HoneypotLog> findByIsBlockedOrderByTimestampDesc(Boolean isBlocked);
    
    List<HoneypotLog> findBySourceIpAndProtocolOrderByTimestampDesc(String sourceIp, String protocol);

    /** Rows at/after the given instant - lets the dashboard's time-windowed stats
     *  (24h / 7d / 30d) pull only the selected window from SQL (served by
     *  idx_honeypot_logs_timestamp) instead of hydrating the whole table. */
    List<HoneypotLog> findByTimestampGreaterThanEqual(LocalDateTime cutoff);

    /** Most-recent N rows (pass a PageRequest of size N), served by
     *  idx_honeypot_logs_timestamp - for "recent events" style endpoints that
     *  only need a small tail, so they stop hydrating the whole table. */
    List<HoneypotLog> findByOrderByTimestampDesc(Pageable pageable);

    /** All-time TTP scan as a lightweight projection: selects ONLY the columns
     *  TTPAnalysisService reads, so the ~91.5k-row recompute no longer hydrates
     *  the heavy {@code payload}/full-entity data. Row count and every field it
     *  keeps are identical to the full scan, so the advertised TTP totals are
     *  unchanged - this is an allocation/GC optimization only. Ordered newest
     *  first (served by idx_honeypot_logs_timestamp), matching the prior
     *  findAllByOrderByTimestampDesc() the TTP code relied on. */
    @Query("SELECT new com.safetech.otshield.dto.TtpLogRow("
         + "h.sourceIp, h.attackType, h.timestamp, h.description, h.protocol, "
         + "h.usernameAttempt, h.userAgent, h.passwordAttempt, h.severity, h.country, h.decoySource) "
         + "FROM HoneypotLog h ORDER BY h.timestamp DESC")
    List<TtpLogRow> findTtpRows();
}

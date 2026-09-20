package com.safetech.otshield.repository;

import com.safetech.otshield.model.HoneypotLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

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
}

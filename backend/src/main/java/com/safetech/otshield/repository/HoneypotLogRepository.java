package com.safetech.otshield.repository;

import com.safetech.otshield.model.HoneypotLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HoneypotLogRepository extends JpaRepository<HoneypotLog, Long> {
    
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

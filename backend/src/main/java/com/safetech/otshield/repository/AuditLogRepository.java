package com.safetech.otshield.repository;

import com.safetech.otshield.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findAllByOrderByCreatedAtDesc();
    List<AuditLog> findByActorOrderByCreatedAtDesc(String actor);
    List<AuditLog> findByActionOrderByCreatedAtDesc(String action);
}

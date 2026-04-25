package com.safetech.otshield.service;

import com.safetech.otshield.mapper.AuditRecord;
import com.safetech.otshield.repository.AuditRecordRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuditService {
    private final AuditRecordRepository repo;

    public AuditService(AuditRecordRepository repo) {
        this.repo = repo;
    }

    public void record(Authentication auth, String actionType, String details) {
        String user = auth != null ? auth.getName() : "anonymous";
        AuditRecord rec = new AuditRecord(user, actionType, details, Instant.now());
        repo.save(rec);
    }
}
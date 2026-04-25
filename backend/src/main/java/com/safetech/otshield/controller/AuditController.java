package com.safetech.otshield.controller;

import com.safetech.otshield.service.AuditService;
import com.safetech.otshield.mapper.AuditRecord;
import com.safetech.otshield.repository.AuditRecordRepository;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;
    private final AuditRecordRepository auditRecordRepository;

    public AuditController(AuditService auditService,
                         AuditRecordRepository auditRecordRepository) {
        this.auditService = auditService;
        this.auditRecordRepository = auditRecordRepository;
    }

    @PostMapping
    public void createRecord(
            @RequestParam String actionType,
            @RequestParam String details,
            Authentication authentication
    ) {
        auditService.record(authentication, actionType, details);
    }

    @GetMapping
    public List<AuditRecord> getAll() {
        // return recent audit records, sorted newest first
        return auditRecordRepository.findAll(Sort.by(Sort.Direction.DESC, "timestamp"));
    }
}
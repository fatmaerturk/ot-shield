package com.safetech.otshield.service;

import com.safetech.otshield.model.BlockingRule;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.repository.BlockingRuleRepository;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

@Service
public class BlockingRuleService {

    private final BlockingRuleRepository repo;

    public BlockingRuleService(BlockingRuleRepository repo) {
        this.repo = repo;
    }

    public List<BlockingRule> list() {
        return repo.findAll();
    }

    public BlockingRule create(BlockingRule r) { return repo.save(r); }
    public BlockingRule update(Long id, BlockingRule r) { r.setId(id); return repo.save(r); }
    public void delete(Long id) { repo.deleteById(id); }

    public boolean shouldBlock(HoneypotLog log) {
        // Evaluate enabled rules; any match that has block=true will block
        return repo.findAll().stream()
                .filter(r -> Boolean.TRUE.equals(r.getEnabled()))
                .sorted(Comparator.comparing(BlockingRule::getId))
                .anyMatch(r -> matches(r, log) && Boolean.TRUE.equals(r.getBlock()));
    }

    private boolean matches(BlockingRule r, HoneypotLog log) {
        if (r.getProtocol() != null && !r.getProtocol().isBlank()) {
            if (!Objects.equals(r.getProtocol().toUpperCase(), safeUpper(log.getProtocol()))) return false;
        }
        if (r.getAttackTypeContains() != null && !r.getAttackTypeContains().isBlank()) {
            String at = log.getAttackType() != null ? log.getAttackType().toLowerCase() : "";
            if (!at.contains(r.getAttackTypeContains().toLowerCase())) return false;
        }
        if (r.getMinSeverity() != null && !r.getMinSeverity().isBlank()) {
            if (severityRank(safeUpper(log.getSeverity())) < severityRank(safeUpper(r.getMinSeverity()))) return false;
        }
        // Reputation score field may not exist/enriched; skip if unavailable
        return true;
    }

    private String safeUpper(String s) { return s == null ? null : s.toUpperCase(); }

    private int severityRank(String s) {
        if (s == null) return 0;
        return switch (s) {
            case "LOW" -> 1;
            case "MEDIUM" -> 2;
            case "HIGH" -> 3;
            default -> 0;
        };
    }
}



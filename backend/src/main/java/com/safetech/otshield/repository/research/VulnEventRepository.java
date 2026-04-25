package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.VulnEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * Repository for {@link VulnEvent}. Append-only - no delete APIs exposed;
 * the cascading delete on the parent observation is the only way rows
 * disappear, which is deliberate.
 */
public interface VulnEventRepository extends JpaRepository<VulnEvent, String> {

    List<VulnEvent> findByVulnIdOrderByCreatedAtAsc(String vulnId);

    void deleteByVulnId(String vulnId);
}

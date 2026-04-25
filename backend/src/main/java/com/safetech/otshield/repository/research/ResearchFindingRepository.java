package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResearchFindingRepository extends JpaRepository<ResearchFinding, String> {

    /** Findings tab listing, most recently created first. */
    List<ResearchFinding> findAllByOrderByCreatedAtDesc();

    /** Faz 4.1: bundle-scoped listing. */
    List<ResearchFinding> findByBundleIdOrderByCreatedAtDesc(String bundleId);
}

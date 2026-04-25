package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchThread;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResearchThreadRepository extends JpaRepository<ResearchThread, String> {

    /** Threads list, most-recently-active first. */
    List<ResearchThread> findAllByOrderByUpdatedAtDesc();

    /** Faz 4.1: bundle-scoped listing. */
    List<ResearchThread> findByBundleIdOrderByUpdatedAtDesc(String bundleId);
}

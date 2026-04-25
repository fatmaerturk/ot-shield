package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.BundleSummary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BundleSummaryRepository extends JpaRepository<BundleSummary, String> {
    // Primary key is the bundle id, so findById(bundleId) is enough.
}

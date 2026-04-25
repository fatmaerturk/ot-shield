package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResearchDocumentRepository extends JpaRepository<ResearchDocument, String> {

    /** Library listing, newest first - drives the Research Studio table. */
    List<ResearchDocument> findAllByOrderByUploadedAtDesc();

    /** Faz 4.1: bundle-scoped listing. */
    List<ResearchDocument> findByBundleIdOrderByUploadedAtDesc(String bundleId);
}

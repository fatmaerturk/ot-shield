package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchDocumentChunk;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResearchDocumentChunkRepository extends JpaRepository<ResearchDocumentChunk, String> {

    /** All chunks belonging to a given document, ordered by reading position. */
    List<ResearchDocumentChunk> findByDocumentIdOrderByOrdinalAsc(String documentId);

    /** Used during the rehydrate-on-startup flow to repopulate the in-memory store. */
    List<ResearchDocumentChunk> findAll();

    /** Clean up chunks when a parent document is deleted. */
    void deleteByDocumentId(String documentId);

    /** Bulk fetch for citation rendering - driven by vector search hits. */
    List<ResearchDocumentChunk> findByIdIn(List<String> ids);
}

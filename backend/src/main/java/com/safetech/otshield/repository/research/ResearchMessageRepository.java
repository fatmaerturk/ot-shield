package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchMessage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResearchMessageRepository extends JpaRepository<ResearchMessage, String> {

    /** Full transcript for a thread, oldest first - drives the Threads tab viewer. */
    List<ResearchMessage> findByThreadIdOrderByCreatedAtAsc(String threadId);

    /** Called when a thread is deleted so we can clear children in one shot. */
    void deleteByThreadId(String threadId);

    /** Running total exposed as {@code ResearchThread.messageCount}. */
    long countByThreadId(String threadId);
}

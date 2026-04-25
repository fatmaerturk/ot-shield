package com.safetech.otshield.repository.research;

import com.safetech.otshield.model.research.ResearchBundle;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ResearchBundleRepository extends JpaRepository<ResearchBundle, String> {

    /** Sidebar order: most recently touched first. */
    List<ResearchBundle> findAllByOrderByUpdatedAtDesc();

    /** Slug is unique per install; used for deep-linking and for the default-bundle seeder. */
    Optional<ResearchBundle> findBySlug(String slug);
}

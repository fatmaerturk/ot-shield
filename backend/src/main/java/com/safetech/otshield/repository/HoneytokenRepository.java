package com.safetech.otshield.repository;

import com.safetech.otshield.model.Honeytoken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HoneytokenRepository extends JpaRepository<Honeytoken, String> {
    List<Honeytoken> findAllByOrderByCreatedAtDesc();
}

package com.safetech.otshield.repository;

import com.safetech.otshield.model.BlockingRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BlockingRuleRepository extends JpaRepository<BlockingRule, Long> {
}



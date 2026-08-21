package com.safetech.otshield.repository;

import com.safetech.otshield.model.DeployedDecoy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DeployedDecoyRepository extends JpaRepository<DeployedDecoy, String> {
}

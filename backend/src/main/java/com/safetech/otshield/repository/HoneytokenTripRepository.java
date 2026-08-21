package com.safetech.otshield.repository;

import com.safetech.otshield.model.HoneytokenTrip;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HoneytokenTripRepository extends JpaRepository<HoneytokenTrip, Long> {
    List<HoneytokenTrip> findTop200ByOrderByTsDesc();
    List<HoneytokenTrip> findByTokenIdOrderByTsDesc(String tokenId);
    boolean existsByTokenIdAndSourceIpAndMethod(String tokenId, String sourceIp, String method);
}

package com.safetech.otshield.dto.research;

/**
 * Drives the 5-card KPI row at the top of the Vulns tab. These numbers
 * were chosen to match the HMGCC review flow: how many are still in the
 * researcher's queue, how many need more evidence, how many are waiting
 * for a verification decision, how many verified high-risk items made
 * it through, and how many were mitigated recently.
 */
public record VulnKpiDTO(
        long openCount,
        long needsMoreSourcesCount,
        long underReviewCount,
        long verifiedHighOrCriticalCount,
        long mitigatedCount
) {}

package com.safetech.otshield.repository;

import com.safetech.otshield.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    
    // Basic queries
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    
    // Status-based queries
    List<User> findByIsActiveTrue();
    List<User> findByIsActiveFalse();
    List<User> findByIsSuspendedTrue();
    List<User> findByIsSuspendedFalse();
    List<User> findByIsAdminTrue();
    List<User> findByIsAdminFalse();
    List<User> findByIsExpiredTrue();
    List<User> findByIsExpiredFalse();
    
    // Count queries
    long countByIsActive(Boolean isActive);
    long countByIsSuspended(Boolean isSuspended);
    long countByIsAdmin(Boolean isAdmin);
    long countByIsExpired(Boolean isExpired);
    
    // Department and role queries
    List<User> findByDepartment(String department);
    List<User> findByRole(String role);
    List<User> findByDepartmentAndIsActiveTrue(String department);
    List<User> findByRoleAndIsActiveTrue(String role);
    
    // Date-based queries
    List<User> findByCreatedAtAfter(LocalDateTime date);
    List<User> findByCreatedAtBefore(LocalDateTime date);
    List<User> findByLastLoginAtAfter(LocalDateTime date);
    List<User> findByLastLoginAtBefore(LocalDateTime date);
    List<User> findByPasswordChangedAtBefore(LocalDateTime date);
    
    // Group queries
    List<User> findByGroupsContaining(String group);
    
    // Source queries
    List<User> findBySource(String source);
    
    // Failed login attempts
    List<User> findByFailedLoginAttemptsGreaterThan(Integer attempts);
    List<User> findByFailedLoginAttemptsGreaterThanAndIsActiveTrue(Integer attempts);
    
    // Password change requirements
    List<User> findByRequiresPasswordChangeTrue();
    List<User> findByRequiresPasswordChangeFalse();
    
    // Manager queries
    List<User> findByManagerId(String managerId);
    
    // Employee ID queries
    Optional<User> findByEmployeeId(String employeeId);
    boolean existsByEmployeeId(String employeeId);
    
    // Username queries
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
    
    // Phone number queries
    Optional<User> findByPhoneNumber(String phoneNumber);
    boolean existsByPhoneNumber(String phoneNumber);
    
    // Search functionality
    @Query("SELECT u FROM User u WHERE " +
           "LOWER(u.fullName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.department) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.jobTitle) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<User> searchUsers(@Param("searchTerm") String searchTerm, Pageable pageable);
    
    // Advanced search with filters
    @Query("SELECT u FROM User u WHERE " +
           "(:department IS NULL OR u.department = :department) AND " +
           "(:role IS NULL OR u.role = :role) AND " +
           "(:isActive IS NULL OR u.isActive = :isActive) AND " +
           "(:isAdmin IS NULL OR u.isAdmin = :isAdmin) AND " +
           "(LOWER(u.fullName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%')))")
    Page<User> searchUsersWithFilters(
            @Param("searchTerm") String searchTerm,
            @Param("department") String department,
            @Param("role") String role,
            @Param("isActive") Boolean isActive,
            @Param("isAdmin") Boolean isAdmin,
            Pageable pageable);
    
    // Statistics queries
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt >= :startDate AND u.createdAt <= :endDate")
    long countByCreatedAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.lastLoginAt >= :startDate AND u.lastLoginAt <= :endDate")
    long countByLastLoginAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
    
    // Department statistics
    @Query("SELECT u.department, COUNT(u) FROM User u WHERE u.department IS NOT NULL GROUP BY u.department")
    List<Object[]> countByDepartment();
    
    // Role statistics
    @Query("SELECT u.role, COUNT(u) FROM User u WHERE u.role IS NOT NULL GROUP BY u.role")
    List<Object[]> countByRole();
    
    // Inactive users (no login in specified days)
    @Query("SELECT u FROM User u WHERE u.lastLoginAt < :date OR u.lastLoginAt IS NULL")
    List<User> findInactiveUsers(@Param("date") LocalDateTime date);
    
    // Users requiring password change
    @Query("SELECT u FROM User u WHERE u.requiresPasswordChange = true OR u.passwordChangedAt < :date")
    List<User> findUsersRequiringPasswordChange(@Param("date") LocalDateTime date);
} 
package com.safetech.otshield.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Data Transfer Object for User entity
 * Excludes sensitive information like password for security
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {
    private String id;
    private String email;
    private String fullName;
    private String username;
    private String role;
    private Boolean isAdmin;
    private Boolean isSuspended;
    private Boolean isExpired;
    private List<String> groups;
    private String source;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLoginAt;
    private String lastLoginIp;
    private Boolean isActive;
    private String department;
    private String phoneNumber;
    private String avatarUrl;
    private String timezone;
    private String language;
    private Integer failedLoginAttempts;
    private LocalDateTime passwordChangedAt;
    private Boolean requiresPasswordChange;
    private String managerId;
    private String employeeId;
    private String jobTitle;
    private String location;
    private String notes;
} 
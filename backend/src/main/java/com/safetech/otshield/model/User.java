package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Data
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    private String fullName;

    private String username;

    private String role;

    private Boolean isAdmin;

    private Boolean isSuspended;

    private Boolean isExpired;

    /**
     * Groups the user belongs to. EAGER because OTShield disables
     * open-in-view (see application.properties) to keep SSE chat
     * streams from holding JDBC connections open - and the User row
     * is read from controllers that then map to a DTO outside any
     * transactional boundary. The list is tiny in practice (handful
     * of strings) so the join cost is negligible.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> groups;

    private String source;

    // Audit fields
    @Column(updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    // Login tracking
    private LocalDateTime lastLoginAt;
    private String lastLoginIp;
    private Boolean isActive;

    // Additional user information
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

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (isActive == null) {
            isActive = true;
        }
        if (failedLoginAttempts == null) {
            failedLoginAttempts = 0;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (isAdmin != null && isAdmin) {
            return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        return List.of(new SimpleGrantedAuthority(role != null ? role : "ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username != null ? username : email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isExpired == null || !isExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isSuspended == null || !isSuspended;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isActive != null ? isActive : true;
    }
}
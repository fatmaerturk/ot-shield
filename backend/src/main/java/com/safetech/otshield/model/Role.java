package com.safetech.otshield.model;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

/**
 * Canonical OTShield RBAC roles, ordered most- to least-privileged.
 *
 * <p>Stored on the {@code users.role} column as {@code "ROLE_<NAME>"} (the format
 * the pre-existing rows already use). {@link #fromStored} tolerates every historic
 * variant - a bare {@code "ADMIN"}, a prefixed {@code "ROLE_ADMIN"}, the legacy
 * {@code "USER"}/{@code "ROLE_USER"} rows (mapped to {@link #VIEWER}), null, or an
 * unknown string (defaults to {@link #VIEWER}) - so the switch to real RBAC never
 * locks an existing account out.
 *
 * <p>Enforcement is via {@link #impliedAuthorities()}: a user is granted its own
 * role plus every role below it, so a single {@code hasRole("VIEWER")} URL rule is
 * satisfied by everyone, {@code hasRole("ANALYST")} by analysts and admins, and so
 * on. This encodes the hierarchy directly in the authorities, which works
 * identically across Spring Security versions without a separate RoleHierarchy
 * bean wiring.
 */
public enum Role {
    ADMIN,      // full control: user management, settings, danger zone
    ANALYST,    // triage incidents, manage alerts/cases, run threat hunts
    OPERATOR,   // day-to-day ICS monitoring; can acknowledge but not delete
    VIEWER;     // read-only dashboard access, no mutations

    /** The Spring Security authority for this exact role, e.g. {@code ROLE_ADMIN}. */
    public String authority() {
        return "ROLE_" + name();
    }

    /** The canonical value to persist on {@code users.role}, e.g. {@code ROLE_ANALYST}. */
    public String stored() {
        return "ROLE_" + name();
    }

    /** True if this role is at least as privileged as {@code other}. */
    public boolean atLeast(Role other) {
        // Lower ordinal == higher privilege (ADMIN is 0).
        return this.ordinal() <= other.ordinal();
    }

    /**
     * This role's authority plus every lower-privileged role's authority, so the
     * role hierarchy is expressed through the granted authorities themselves.
     */
    public List<SimpleGrantedAuthority> impliedAuthorities() {
        List<SimpleGrantedAuthority> out = new ArrayList<>();
        for (Role r : values()) {
            if (r.ordinal() >= this.ordinal()) {   // self + everything below
                out.add(new SimpleGrantedAuthority(r.authority()));
            }
        }
        return out;
    }

    /**
     * Resolve the effective role from the stored {@code role} string and the legacy
     * {@code isAdmin} flag. {@code isAdmin == true} always wins (returns {@link #ADMIN}).
     * Everything is normalised: an optional {@code ROLE_} prefix is stripped, case is
     * ignored, legacy {@code USER} maps to {@link #VIEWER}, and anything unrecognised
     * (including null/blank) falls back to {@link #VIEWER} (least privilege).
     */
    public static Role fromStored(String role, Boolean isAdmin) {
        if (Boolean.TRUE.equals(isAdmin)) {
            return ADMIN;
        }
        if (role == null || role.isBlank()) {
            return VIEWER;
        }
        String n = role.trim().toUpperCase();
        if (n.startsWith("ROLE_")) {
            n = n.substring("ROLE_".length());
        }
        if (n.equals("USER")) {        // legacy catch-all -> read-only
            return VIEWER;
        }
        for (Role r : values()) {
            if (r.name().equals(n)) {
                return r;
            }
        }
        return VIEWER;
    }

    /** Parse a user-supplied role name (API input) to a canonical role, or null if invalid. */
    public static Role parse(String role) {
        if (role == null || role.isBlank()) {
            return null;
        }
        String n = role.trim().toUpperCase();
        if (n.startsWith("ROLE_")) {
            n = n.substring("ROLE_".length());
        }
        if (n.equals("USER")) {
            return VIEWER;
        }
        for (Role r : values()) {
            if (r.name().equals(n)) {
                return r;
            }
        }
        return null;
    }
}

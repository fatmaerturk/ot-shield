package com.safetech.otshield.controller;

import com.safetech.otshield.dto.UserDTO;
import com.safetech.otshield.mapper.UserMapper;
import com.safetech.otshield.model.Role;
import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
import com.safetech.otshield.service.SettingsService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST Controller for managing users (CRUD + lifecycle).
 *
 * <p>Every endpoint except {@code /me} is ADMIN-only (enforced in SecurityConfig).
 * On top of that URL rule, the mutating endpoints here add in-code guardrails that
 * a bare {@code hasRole(ADMIN)} cannot express:
 * <ul>
 *   <li><b>Self-protection</b> - an admin cannot delete, suspend or demote their
 *       own account (prevents accidental self-lockout).</li>
 *   <li><b>Last-admin protection</b> - the final active admin cannot be deleted,
 *       suspended or demoted, so the platform can never be left without an admin.</li>
 *   <li><b>Audit trail</b> - every create/update/delete/suspend/activate/role-change/
 *       password-reset/unlock writes an {@code audit_logs} row (actor, target, source
 *       IP, outcome) surfaced in Settings &rarr; Audit Log.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final SettingsService settingsService;

    private static final SecureRandom RNG = new SecureRandom();

    // ───────────────────────────────────────────────────────────
    // READ
    // ───────────────────────────────────────────────────────────

    /** Get the current authenticated user (allowed for any role, not just admins). */
    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser() {
        return userRepository.findByEmail(actor())
                .map(userMapper::toDto)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public ResponseEntity<Page<UserDTO>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {

        Sort sort = sortDir.equalsIgnoreCase("ASC") ?
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<UserDTO> userDtos = userRepository.findAll(pageable).map(userMapper::toDto);
        return ResponseEntity.ok(userDtos);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable String id) {
        return userRepository.findById(id)
                .map(userMapper::toDto)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDTO> getUserByEmail(@PathVariable String email) {
        return userRepository.findByEmail(email)
                .map(userMapper::toDto)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/active")
    public ResponseEntity<List<UserDTO>> getActiveUsers() {
        return ResponseEntity.ok(toDtos(userRepository.findByIsActiveTrue()));
    }

    @GetMapping("/suspended")
    public ResponseEntity<List<UserDTO>> getSuspendedUsers() {
        return ResponseEntity.ok(toDtos(userRepository.findByIsSuspendedTrue()));
    }

    @GetMapping("/admins")
    public ResponseEntity<List<UserDTO>> getAdminUsers() {
        return ResponseEntity.ok(toDtos(userRepository.findByIsAdminTrue()));
    }

    @GetMapping("/department/{department}")
    public ResponseEntity<List<UserDTO>> getUsersByDepartment(@PathVariable String department) {
        return ResponseEntity.ok(toDtos(userRepository.findByDepartment(department)));
    }

    @GetMapping("/role/{role}")
    public ResponseEntity<List<UserDTO>> getUsersByRole(@PathVariable String role) {
        return ResponseEntity.ok(toDtos(userRepository.findByRole(role)));
    }

    @GetMapping("/search")
    public ResponseEntity<Page<UserDTO>> searchUsers(
            @RequestParam String searchTerm,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<UserDTO> userDtos = userRepository.searchUsers(searchTerm, pageable).map(userMapper::toDto);
        return ResponseEntity.ok(userDtos);
    }

    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getUserStatistics() {
        Map<String, Object> stats = Map.of(
            "totalUsers", userRepository.count(),
            "activeUsers", userRepository.countByIsActive(true),
            "suspendedUsers", userRepository.countByIsSuspended(true),
            "adminUsers", userRepository.countByIsAdmin(true),
            "expiredUsers", userRepository.countByIsExpired(true)
        );
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/recent")
    public ResponseEntity<List<UserDTO>> getRecentUsers() {
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
        return ResponseEntity.ok(toDtos(userRepository.findByCreatedAtAfter(thirtyDaysAgo)));
    }

    // ───────────────────────────────────────────────────────────
    // CREATE / UPDATE / DELETE
    // ───────────────────────────────────────────────────────────

    /**
     * Create a new user. A strong random temporary password is generated server-side
     * and returned ONCE in the response ({@code tempPassword}); the new account is
     * flagged {@code requiresPasswordChange} so it must be rotated on first use. The
     * role is normalised to a canonical role (default VIEWER = read-only).
     */
    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody UserDTO userDto, HttpServletRequest req) {
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            return ResponseEntity.badRequest().body(err("Email is required"));
        }
        if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body(err("A user with this email already exists"));
        }
        if (userDto.getUsername() != null && !userDto.getUsername().isBlank()
                && userRepository.existsByUsername(userDto.getUsername())) {
            return ResponseEntity.badRequest().body(err("That username is already taken"));
        }

        Role role = Optional.ofNullable(Role.parse(userDto.getRole())).orElse(Role.VIEWER);

        User user = new User();
        user.setEmail(userDto.getEmail().trim());
        user.setFullName(userDto.getFullName());
        user.setUsername(userDto.getUsername());
        user.setDepartment(userDto.getDepartment());
        user.setJobTitle(userDto.getJobTitle());
        user.setRole(role.stored());
        user.setIsAdmin(role == Role.ADMIN);
        user.setIsActive(true);
        user.setIsSuspended(false);

        String tempPassword = generateTempPassword();
        user.setPassword(passwordEncoder.encode(tempPassword));
        user.setRequiresPasswordChange(true);
        user.setPasswordChangedAt(LocalDateTime.now());

        User saved = userRepository.save(user);
        audit(req, "USER_CREATED", "Created user " + saved.getEmail() + " with role " + role.name(),
              saved.getId(), "SUCCESS");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user", userMapper.toDto(saved));
        body.put("tempPassword", tempPassword);   // shown to the admin once; never persisted in clear
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    /**
     * Update an existing user's profile fields. Only mutable profile fields are
     * copied from the DTO; password, login-tracking, lock state, suspension/active
     * flags and audit timestamps are preserved from the stored record (they have
     * dedicated endpoints). A role change routes through the same guardrails as
     * {@link #changeRole}.
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable String id, @RequestBody UserDTO dto,
                                        HttpServletRequest req) {
        User existing = userRepository.findById(id).orElse(null);
        if (existing == null) {
            return ResponseEntity.notFound().build();
        }

        // Username uniqueness (if being changed).
        if (dto.getUsername() != null && !dto.getUsername().isBlank()
                && !dto.getUsername().equals(existing.getUsername())
                && userRepository.existsByUsername(dto.getUsername())) {
            return ResponseEntity.badRequest().body(err("That username is already taken"));
        }

        // Copy only mutable profile fields (null = leave unchanged, never wipe).
        if (dto.getFullName() != null)    existing.setFullName(dto.getFullName());
        if (dto.getUsername() != null)    existing.setUsername(dto.getUsername());
        if (dto.getDepartment() != null)  existing.setDepartment(dto.getDepartment());
        if (dto.getPhoneNumber() != null) existing.setPhoneNumber(dto.getPhoneNumber());
        if (dto.getJobTitle() != null)    existing.setJobTitle(dto.getJobTitle());
        if (dto.getLocation() != null)    existing.setLocation(dto.getLocation());
        if (dto.getNotes() != null)       existing.setNotes(dto.getNotes());
        if (dto.getTimezone() != null)    existing.setTimezone(dto.getTimezone());
        if (dto.getLanguage() != null)    existing.setLanguage(dto.getLanguage());
        if (dto.getEmployeeId() != null)  existing.setEmployeeId(dto.getEmployeeId());
        if (dto.getManagerId() != null)   existing.setManagerId(dto.getManagerId());
        if (dto.getAvatarUrl() != null)   existing.setAvatarUrl(dto.getAvatarUrl());
        if (dto.getGroups() != null)      existing.setGroups(dto.getGroups());

        // Role change (if requested) goes through the privilege guards.
        if (dto.getRole() != null && !dto.getRole().isBlank()) {
            Role newRole = Role.parse(dto.getRole());
            if (newRole == null) {
                return ResponseEntity.badRequest().body(err("Unknown role: " + dto.getRole()));
            }
            ResponseEntity<?> guard = applyRoleChange(existing, newRole, req);
            if (guard != null) return guard;   // guard produced an error response
        }

        User saved = userRepository.save(existing);
        audit(req, "USER_UPDATED", "Updated profile for " + saved.getEmail(), saved.getId(), "SUCCESS");
        return ResponseEntity.ok(userMapper.toDto(saved));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id, HttpServletRequest req) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) {
            return ResponseEntity.notFound().build();
        }
        if (isSelf(target)) {
            return conflict(req, "USER_DELETE_BLOCKED", "self-delete", target, "You cannot delete your own account");
        }
        if (isLastActiveAdmin(target)) {
            return conflict(req, "USER_DELETE_BLOCKED", "last-admin", target,
                    "Cannot delete the last active administrator");
        }
        userRepository.deleteById(id);
        audit(req, "USER_DELETED", "Deleted user " + target.getEmail(), id, "SUCCESS");
        return ResponseEntity.noContent().build();
    }

    // ───────────────────────────────────────────────────────────
    // LIFECYCLE: suspend / activate / unlock / role / password
    // ───────────────────────────────────────────────────────────

    @PostMapping("/{id}/suspend")
    public ResponseEntity<?> suspendUser(@PathVariable String id, HttpServletRequest req) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) return ResponseEntity.notFound().build();
        if (isSelf(target)) {
            return conflict(req, "USER_SUSPEND_BLOCKED", "self-suspend", target, "You cannot suspend your own account");
        }
        if (isLastActiveAdmin(target)) {
            return conflict(req, "USER_SUSPEND_BLOCKED", "last-admin", target,
                    "Cannot suspend the last active administrator");
        }
        target.setIsSuspended(true);
        target.setIsActive(false);
        User saved = userRepository.save(target);
        audit(req, "USER_SUSPENDED", "Suspended user " + target.getEmail(), id, "SUCCESS");
        return ResponseEntity.ok(userMapper.toDto(saved));
    }

    @PostMapping("/{id}/activate")
    public ResponseEntity<?> activateUser(@PathVariable String id, HttpServletRequest req) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) return ResponseEntity.notFound().build();
        target.setIsSuspended(false);
        target.setIsActive(true);
        target.setLockedUntil(null);        // reactivation also clears any lockout
        target.setFailedLoginAttempts(0);
        User saved = userRepository.save(target);
        audit(req, "USER_ACTIVATED", "Activated user " + target.getEmail(), id, "SUCCESS");
        return ResponseEntity.ok(userMapper.toDto(saved));
    }

    /** Clear a failed-login lockout (admin-initiated). */
    @PostMapping("/{id}/unlock")
    public ResponseEntity<?> unlockUser(@PathVariable String id, HttpServletRequest req) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) return ResponseEntity.notFound().build();
        target.setLockedUntil(null);
        target.setFailedLoginAttempts(0);
        User saved = userRepository.save(target);
        audit(req, "USER_UNLOCKED", "Cleared login lockout for " + target.getEmail(), id, "SUCCESS");
        return ResponseEntity.ok(userMapper.toDto(saved));
    }

    /** Change a user's role (ADMIN/ANALYST/OPERATOR/VIEWER), with privilege guards. */
    @PostMapping("/{id}/role")
    public ResponseEntity<?> changeRole(@PathVariable String id,
                                        @RequestBody Map<String, String> request,
                                        HttpServletRequest req) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) return ResponseEntity.notFound().build();

        Role newRole = Role.parse(request.get("role"));
        if (newRole == null) {
            return ResponseEntity.badRequest().body(err("Unknown role: " + request.get("role")));
        }
        ResponseEntity<?> guard = applyRoleChange(target, newRole, req);
        if (guard != null) return guard;

        User saved = userRepository.save(target);
        return ResponseEntity.ok(userMapper.toDto(saved));
    }

    @PostMapping("/{id}/change-password")
    public ResponseEntity<?> changePassword(@PathVariable String id,
                                            @RequestBody Map<String, String> request,
                                            HttpServletRequest req) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) return ResponseEntity.notFound().build();

        String newPassword = request.get("newPassword");
        String policyError = passwordPolicyError(newPassword);
        if (policyError != null) {
            return ResponseEntity.badRequest().body(err(policyError));
        }

        target.setPassword(passwordEncoder.encode(newPassword));
        target.setPasswordChangedAt(LocalDateTime.now());
        target.setRequiresPasswordChange(false);
        target.setFailedLoginAttempts(0);
        target.setLockedUntil(null);        // a password reset also clears a lockout
        User saved = userRepository.save(target);
        audit(req, "PASSWORD_RESET", "Reset password for " + target.getEmail(), id, "SUCCESS");
        return ResponseEntity.ok(userMapper.toDto(saved));
    }

    // ───────────────────────────────────────────────────────────
    // GUARDS & HELPERS
    // ───────────────────────────────────────────────────────────

    /**
     * Apply a role change to {@code target} in-place after the privilege guards.
     * Returns null on success (caller then saves), or an error ResponseEntity if a
     * guard blocked it. Blocks demoting your own admin account or the last admin.
     */
    private ResponseEntity<?> applyRoleChange(User target, Role newRole, HttpServletRequest req) {
        Role currentRole = target.effectiveRole();
        if (currentRole == newRole) {
            return null;   // no-op
        }
        boolean demotingFromAdmin = currentRole == Role.ADMIN && newRole != Role.ADMIN;
        if (demotingFromAdmin && isSelf(target)) {
            return conflict(req, "ROLE_CHANGE_BLOCKED", "self-demote", target,
                    "You cannot change your own admin role");
        }
        if (demotingFromAdmin && isLastActiveAdmin(target)) {
            return conflict(req, "ROLE_CHANGE_BLOCKED", "last-admin", target,
                    "Cannot demote the last active administrator");
        }
        target.setRole(newRole.stored());
        target.setIsAdmin(newRole == Role.ADMIN);
        audit(req, "ROLE_CHANGED",
              target.getEmail() + ": " + currentRole.name() + " -> " + newRole.name(),
              target.getId(), "SUCCESS");
        return null;
    }

    /** True if the target account is the acting admin's own account. */
    private boolean isSelf(User target) {
        String me = actor();
        return me != null && (me.equalsIgnoreCase(target.getEmail())
                || me.equalsIgnoreCase(target.getUsername()));
    }

    /** True if target is an active admin and the only one left. */
    private boolean isLastActiveAdmin(User target) {
        return isActiveAdmin(target) && activeAdminCount() <= 1;
    }

    private boolean isActiveAdmin(User u) {
        return u.effectiveRole() == Role.ADMIN
                && !Boolean.FALSE.equals(u.getIsActive())
                && !Boolean.TRUE.equals(u.getIsSuspended());
    }

    private long activeAdminCount() {
        return userRepository.findAll().stream().filter(this::isActiveAdmin).count();
    }

    /** Minimum password policy: >= 10 chars with at least one upper, lower and digit. */
    private String passwordPolicyError(String pwd) {
        if (pwd == null || pwd.length() < 10) {
            return "Password must be at least 10 characters";
        }
        boolean upper = pwd.chars().anyMatch(Character::isUpperCase);
        boolean lower = pwd.chars().anyMatch(Character::isLowerCase);
        boolean digit = pwd.chars().anyMatch(Character::isDigit);
        if (!(upper && lower && digit)) {
            return "Password must include an uppercase letter, a lowercase letter and a digit";
        }
        return null;
    }

    private String generateTempPassword() {
        // 12 chars drawn from upper/lower/digit/symbol, guaranteeing the policy classes.
        String upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        String lower = "abcdefghijkmnpqrstuvwxyz";
        String digit = "23456789";
        String sym   = "!@#$%*?";
        String all   = upper + lower + digit + sym;
        StringBuilder sb = new StringBuilder();
        sb.append(upper.charAt(RNG.nextInt(upper.length())));
        sb.append(lower.charAt(RNG.nextInt(lower.length())));
        sb.append(digit.charAt(RNG.nextInt(digit.length())));
        sb.append(sym.charAt(RNG.nextInt(sym.length())));
        for (int i = 0; i < 8; i++) {
            sb.append(all.charAt(RNG.nextInt(all.length())));
        }
        // Shuffle so the guaranteed classes are not always in the first positions.
        char[] arr = sb.toString().toCharArray();
        for (int i = arr.length - 1; i > 0; i--) {
            int j = RNG.nextInt(i + 1);
            char t = arr[i]; arr[i] = arr[j]; arr[j] = t;
        }
        return new String(arr);
    }

    private List<UserDTO> toDtos(List<User> users) {
        return users.stream().map(userMapper::toDto).collect(Collectors.toList());
    }

    private Map<String, Object> err(String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", message);
        return m;
    }

    /** Build a 409 CONFLICT response and write a FAILURE audit row for a blocked action. */
    private ResponseEntity<Map<String, Object>> conflict(HttpServletRequest req, String action,
                                                         String reason, User target, String message) {
        audit(req, action, message + " (" + target.getEmail() + ")", target.getId(), "FAILURE");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", message);
        m.put("reason", reason);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(m);
    }

    private void audit(HttpServletRequest req, String action, String description,
                       String targetId, String outcome) {
        try {
            settingsService.log(actor(), action, description, "user", targetId, clientIp(req), outcome);
        } catch (Exception ignored) {
            // audit is best-effort; it must never break the operation
        }
    }

    private String actor() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a != null ? a.getName() : "system";
    }

    private String clientIp(HttpServletRequest req) {
        if (req == null) return null;
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String xri = req.getHeader("X-Real-IP");
        if (xri != null && !xri.isBlank()) return xri.trim();
        return req.getRemoteAddr();
    }
}

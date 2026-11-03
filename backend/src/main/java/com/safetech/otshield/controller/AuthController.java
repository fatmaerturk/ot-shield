package com.safetech.otshield.controller;

import com.safetech.otshield.dto.LoginRequest;
import com.safetech.otshield.dto.LoginResponse;
import com.safetech.otshield.dto.RegisterRequest;
import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
import com.safetech.otshield.service.AuthService;
import com.safetech.otshield.service.SettingsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SettingsService settingsService;

    // Self-service registration and the debug oracle are OFF by default (secure
    // for prod). Dev turns them on in application.properties. On a public
    // deployment, open registration would hand any visitor an authenticated
    // account, and /debug reveals whether a given password matches - both are
    // fail-closed here.
    @Value("${auth.registration.enabled:false}")
    private boolean registrationEnabled;

    @Value("${auth.debug.enabled:false}")
    private boolean debugEnabled;

    // Failed-login lockout: after `maxAttempts` consecutive failures an account is
    // locked for `lockoutMinutes`. Tunable via config; defaults are a sane
    // enterprise baseline. A successful login or an admin unlock resets the counter.
    @Value("${security.lockout.max-attempts:5}")
    private int maxAttempts;

    @Value("${security.lockout.minutes:15}")
    private int lockoutMinutes;

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        if (!registrationEnabled) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request,
                                   HttpServletRequest httpRequest) {
        String ip = clientIp(httpRequest);
        String email = request.getEmail();

        // Pre-check: if the account is currently locked out, reject BEFORE touching
        // the password so a locked account can't be probed. Returns 423 LOCKED with
        // a clear message; the login page surfaces it (the axios 401 interceptor,
        // which refreshes/redirects, deliberately does not fire on 423).
        User existing = userRepository.findByEmail(email).orElse(null);
        if (existing != null && existing.getLockedUntil() != null
                && existing.getLockedUntil().isAfter(LocalDateTime.now())) {
            long mins = Math.max(1,
                java.time.Duration.between(LocalDateTime.now(), existing.getLockedUntil()).toMinutes() + 1);
            recordLogin(email, ip, "FAILURE", "Login blocked: account locked");
            Map<String, Object> body = new HashMap<>();
            body.put("status", 423);
            body.put("error", "Account locked");
            body.put("message", "Too many failed attempts. Try again in about " + mins + " minute(s).");
            return ResponseEntity.status(HttpStatus.LOCKED).body(body);
        }

        try {
            LoginResponse response = authService.login(request);
            onLoginSuccess(email, ip);
            recordLogin(email, ip, "SUCCESS", "Signed in");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            // Count the failed attempt (and lock if the threshold is reached), log it,
            // then let it propagate so the client still gets its 401.
            onLoginFailure(existing, ip);
            recordLogin(email, ip, "FAILURE", "Login failed: " + e.getMessage());
            throw e;
        }
    }

    /** Write a LOGIN audit-trail row. Never let an audit failure break login. */
    private void recordLogin(String email, String ip, String outcome, String description) {
        try {
            settingsService.log(email, "LOGIN", description, "user", email, ip, outcome);
        } catch (Exception ignored) {
            // audit is best-effort; a persistence hiccup must not block authentication
        }
    }

    /**
     * On success: stamp last-login time/IP and clear any failed-attempt counter and
     * lockout (best-effort - a persistence hiccup must not block a valid sign-in).
     */
    private void onLoginSuccess(String email, String ip) {
        try {
            userRepository.findByEmail(email).ifPresent(u -> {
                u.setLastLoginAt(LocalDateTime.now());
                u.setLastLoginIp(ip);
                u.setFailedLoginAttempts(0);
                u.setLockedUntil(null);
                userRepository.save(u);
            });
        } catch (Exception ignored) {
        }
    }

    /**
     * On failure: increment the failed-attempt counter for a KNOWN account and lock
     * it once the threshold is reached. Unknown emails are ignored (no row to lock,
     * and we must not reveal whether the account exists). Best-effort.
     */
    private void onLoginFailure(User existing, String ip) {
        if (existing == null) {
            return;
        }
        try {
            int attempts = (existing.getFailedLoginAttempts() == null ? 0
                    : existing.getFailedLoginAttempts()) + 1;
            existing.setFailedLoginAttempts(attempts);
            if (attempts >= maxAttempts) {
                existing.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutMinutes));
                existing.setFailedLoginAttempts(0);   // reset the counter once locked
                recordLogin(existing.getEmail(), ip, "FAILURE",
                        "Account locked after " + maxAttempts + " failed attempts");
                settingsService.log("system", "ACCOUNT_LOCKED",
                        "Account locked for " + lockoutMinutes + " min after "
                                + maxAttempts + " failed login attempts",
                        "user", existing.getEmail(), ip, "FAILURE");
            }
            userRepository.save(existing);
        } catch (Exception ignored) {
        }
    }

    /**
     * Real client IP behind the Caddy -> nginx reverse-proxy chain. nginx sets
     * X-Forwarded-For (client first, then proxies); fall back to X-Real-IP and
     * finally the direct socket address.
     */
    private String clientIp(HttpServletRequest req) {
        if (req == null) return null;
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String xri = req.getHeader("X-Real-IP");
        if (xri != null && !xri.isBlank()) {
            return xri.trim();
        }
        return req.getRemoteAddr();
    }

    @PostMapping("/debug")
    public ResponseEntity<Map<String, Object>> debugUser(@RequestBody LoginRequest request) {
        if (!debugEnabled) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        Map<String, Object> debugInfo = new HashMap<>();
        try {
            User user = userRepository.findByEmail(request.getEmail()).orElse(null);
            if (user != null) {
                debugInfo.put("userExists", true);
                debugInfo.put("email", user.getEmail());
                debugInfo.put("username", user.getUsername());
                debugInfo.put("authorities", user.getAuthorities());
                debugInfo.put("isActive", user.isEnabled());
                debugInfo.put("accountNonLocked", user.isAccountNonLocked());
                debugInfo.put("accountNonExpired", user.isAccountNonExpired());
                debugInfo.put("credentialsNonExpired", user.isCredentialsNonExpired());
                
                // Test password matching
                boolean passwordMatches = passwordEncoder.matches(request.getPassword(), user.getPassword());
                debugInfo.put("passwordMatches", passwordMatches);
            } else {
                debugInfo.put("userExists", false);
            }
        } catch (Exception e) {
            debugInfo.put("error", e.getMessage());
        }
        return ResponseEntity.ok(debugInfo);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() {
        // In a stateless JWT setup, logout is handled client-side by removing the token
        // This endpoint can be used to log the logout action
        Map<String, String> response = new HashMap<>();
        response.put("message", "Logout successful. Please remove the JWT token from your client.");
        return ResponseEntity.ok(response);
    }
} 
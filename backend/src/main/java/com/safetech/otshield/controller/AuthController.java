package com.safetech.otshield.controller;

import com.safetech.otshield.dto.LoginRequest;
import com.safetech.otshield.dto.LoginResponse;
import com.safetech.otshield.dto.RegisterRequest;
import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
import com.safetech.otshield.service.AuthService;
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

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Self-service registration and the debug oracle are OFF by default (secure
    // for prod). Dev turns them on in application.properties. On a public
    // deployment, open registration would hand any visitor an authenticated
    // account, and /debug reveals whether a given password matches - both are
    // fail-closed here.
    @Value("${auth.registration.enabled:false}")
    private boolean registrationEnabled;

    @Value("${auth.debug.enabled:false}")
    private boolean debugEnabled;

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        if (!registrationEnabled) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
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
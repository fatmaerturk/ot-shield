package com.safetech.otshield.service;

import com.safetech.otshield.dto.LoginRequest;
import com.safetech.otshield.dto.LoginResponse;
import com.safetech.otshield.dto.RegisterRequest;
import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
import com.safetech.otshield.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public LoginResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFullName(request.getFullName());

        user = userRepository.save(user);
        String token = jwtService.generateToken(user);

        return new LoginResponse(token, user.getEmail(), user.getFullName());
    }

    public LoginResponse login(LoginRequest request) {
        try {
            log.debug("Attempting login for user: {}", request.getEmail());
            
            // Check if user exists first
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            
            log.debug("User found: email={}, username={}, authorities={}", 
                     user.getEmail(), user.getUsername(), user.getAuthorities());
            
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
                )
            );

            log.debug("Authentication successful for user: {}", request.getEmail());

            String token = jwtService.generateToken(user);
            log.debug("Login successful for user: {}", request.getEmail());
            return new LoginResponse(token, user.getEmail(), user.getFullName());
        } catch (BadCredentialsException e) {
            log.error("Invalid credentials for user: {}", request.getEmail());
            throw new BadCredentialsException("Invalid email or password");
        } catch (Exception e) {
            log.error("Login error for user: {}", request.getEmail(), e);
            throw new RuntimeException("An error occurred during login");
        }
    }

} 
package com.safetech.otshield.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import com.safetech.otshield.security.CustomUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final CustomUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf()
            .disable()
            .authorizeHttpRequests()
            // Public by necessity - these cannot rely on a per-request user JWT:
            //   /api/auth              login / register (issues the JWT)
            //   /api/honeypot          ingest sidecar authenticates with its own
            //                          bearer token; /events is an EventSource (SSE)
            //                          which cannot set an Authorization header
            //   /api/honeytoken/hit    attacker-facing decoy trip callback
            //   /api/assistant         SSE via SseEmitter - Spring re-dispatches the
            //                          async request to finalise the stream, and our
            //                          stateless JWT auth is not restored on that
            //                          async dispatch, so requiring auth here yields
            //                          an AccessDenied on completion. Keep it open.
            //   /api/upload            pcap upload flow (kept open for now)
            //   /pcap, /ws             streaming / websocket surfaces
            .requestMatchers(
                "/error",
                "/api/auth/**",
                "/api/upload/**",
                "/api/honeypot/**",
                "/api/honeytoken/hit/**",
                "/api/assistant/**",
                "/pcap/**", "/ws/**", "/pcap/interfaces", "/pcap/pcap-interfaces"
            )
            .permitAll()
            .requestMatchers("/api/anomalies/**").hasAnyRole("ADMIN", "ANALYST", "USER")
            .requestMatchers("/api/assets/**").hasAnyRole("ADMIN", "ANALYST", "USER")
            .requestMatchers("/api/alerts/**").hasAnyRole("ADMIN", "ANALYST", "USER")
            .requestMatchers("/api/users/**").hasRole("ADMIN")
            // Everything else (cases, decoy, deception, settings, research,
            // engage, threat-intel, compliance, conpot, honeytoken management,
            // ...) now requires an authenticated user. The frontend attaches the
            // JWT to every request via an axios interceptor.
            .anyRequest()
            .authenticated()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://127.0.0.1:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        source.registerCorsConfiguration("/api/conpot/**", configuration);
        source.registerCorsConfiguration("/api/honeypot/**", configuration);
        source.registerCorsConfiguration("/pcap/**", configuration);
        source.registerCorsConfiguration("/ws/**", configuration);
        source.registerCorsConfiguration("/pcap/interfaces", configuration);
        source.registerCorsConfiguration("/pcap/pcap-interfaces", configuration);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
} 
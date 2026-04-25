package com.safetech.otshield.controller;

import com.safetech.otshield.dto.UserDTO;
import com.safetech.otshield.mapper.UserMapper;
import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
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

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST Controller for managing users
 * Provides CRUD operations and user management capabilities
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    /**
     * Get current authenticated user
     * @return Current user DTO
     */
    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        
        return userRepository.findByEmail(email)
                .map(userMapper::toDto)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Get all users with pagination and sorting
     * @param page Page number (default: 0)
     * @param size Page size (default: 20)
     * @param sortBy Sort field (default: createdAt)
     * @param sortDir Sort direction (default: DESC)
     * @return Paginated list of user DTOs
     */
    @GetMapping
    public ResponseEntity<Page<UserDTO>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {
        
        Sort sort = sortDir.equalsIgnoreCase("ASC") ? 
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<User> users = userRepository.findAll(pageable);
        Page<UserDTO> userDtos = users.map(userMapper::toDto);
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Get user by ID
     * @param id User ID
     * @return User DTO details or 404 if not found
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable String id) {
        Optional<User> user = userRepository.findById(id);
        return user.map(userMapper::toDto)
                  .map(ResponseEntity::ok)
                  .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Get user by email
     * @param email User email
     * @return User DTO details or 404 if not found
     */
    @GetMapping("/email/{email}")
    public ResponseEntity<UserDTO> getUserByEmail(@PathVariable String email) {
        Optional<User> user = userRepository.findByEmail(email);
        return user.map(userMapper::toDto)
                  .map(ResponseEntity::ok)
                  .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new user
     * @param userDto User DTO data to create
     * @return Created user DTO with generated ID
     */
    @PostMapping
    public ResponseEntity<UserDTO> createUser(@RequestBody UserDTO userDto) {
        // Check if user with same email already exists
        if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().build();
        }
        
        User user = userMapper.toEntity(userDto);
        // Password should be handled separately in a secure way
        // For now, we'll set a default password that should be changed
        user.setPassword(passwordEncoder.encode("changeme"));
        user.setRequiresPasswordChange(true);
        
        User savedUser = userRepository.save(user);
        UserDTO savedUserDto = userMapper.toDto(savedUser);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedUserDto);
    }

    /**
     * Update an existing user
     * @param id User ID
     * @param userDto Updated user DTO data
     * @return Updated user DTO or 404 if not found
     */
    @PutMapping("/{id}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable String id, @RequestBody UserDTO userDto) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userMapper.toEntity(userDto);
        user.setId(id);
        // Don't update password through this endpoint
        User existingUser = userRepository.findById(id).orElse(null);
        if (existingUser != null) {
            user.setPassword(existingUser.getPassword());
        }
        
        User updatedUser = userRepository.save(user);
        UserDTO updatedUserDto = userMapper.toDto(updatedUser);
        return ResponseEntity.ok(updatedUserDto);
    }

    /**
     * Delete a user
     * @param id User ID
     * @return 204 No Content on success
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        userRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Get active users
     * @return List of active user DTOs
     */
    @GetMapping("/active")
    public ResponseEntity<List<UserDTO>> getActiveUsers() {
        List<User> users = userRepository.findByIsActiveTrue();
        List<UserDTO> userDtos = users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Get suspended users
     * @return List of suspended user DTOs
     */
    @GetMapping("/suspended")
    public ResponseEntity<List<UserDTO>> getSuspendedUsers() {
        List<User> users = userRepository.findByIsSuspendedTrue();
        List<UserDTO> userDtos = users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Get admin users
     * @return List of admin user DTOs
     */
    @GetMapping("/admins")
    public ResponseEntity<List<UserDTO>> getAdminUsers() {
        List<User> users = userRepository.findByIsAdminTrue();
        List<UserDTO> userDtos = users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Get users by department
     * @param department Department name
     * @return List of user DTOs in the specified department
     */
    @GetMapping("/department/{department}")
    public ResponseEntity<List<UserDTO>> getUsersByDepartment(@PathVariable String department) {
        List<User> users = userRepository.findByDepartment(department);
        List<UserDTO> userDtos = users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Get users by role
     * @param role User role
     * @return List of user DTOs with the specified role
     */
    @GetMapping("/role/{role}")
    public ResponseEntity<List<UserDTO>> getUsersByRole(@PathVariable String role) {
        List<User> users = userRepository.findByRole(role);
        List<UserDTO> userDtos = users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Search users by text in name, email, or username
     * @param searchTerm Search term
     * @param page Page number
     * @param size Page size
     * @return Paginated search results as DTOs
     */
    @GetMapping("/search")
    public ResponseEntity<Page<UserDTO>> searchUsers(
            @RequestParam String searchTerm,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<User> users = userRepository.searchUsers(searchTerm, pageable);
        Page<UserDTO> userDtos = users.map(userMapper::toDto);
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Suspend a user
     * @param id User ID
     * @param request Request containing suspendedBy
     * @return Updated user DTO
     */
    @PostMapping("/{id}/suspend")
    public ResponseEntity<UserDTO> suspendUser(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<User> userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userOpt.get();
        user.setIsSuspended(true);
        user.setIsActive(false);
        
        User updatedUser = userRepository.save(user);
        UserDTO updatedUserDto = userMapper.toDto(updatedUser);
        return ResponseEntity.ok(updatedUserDto);
    }

    /**
     * Activate a user
     * @param id User ID
     * @return Updated user DTO
     */
    @PostMapping("/{id}/activate")
    public ResponseEntity<UserDTO> activateUser(@PathVariable String id) {
        Optional<User> userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userOpt.get();
        user.setIsSuspended(false);
        user.setIsActive(true);
        
        User updatedUser = userRepository.save(user);
        UserDTO updatedUserDto = userMapper.toDto(updatedUser);
        return ResponseEntity.ok(updatedUserDto);
    }

    /**
     * Update user password
     * @param id User ID
     * @param request Request containing new password
     * @return Updated user DTO
     */
    @PostMapping("/{id}/change-password")
    public ResponseEntity<UserDTO> changePassword(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<User> userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userOpt.get();
        user.setPassword(passwordEncoder.encode(request.get("newPassword")));
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setRequiresPasswordChange(false);
        user.setFailedLoginAttempts(0);
        
        User updatedUser = userRepository.save(user);
        UserDTO updatedUserDto = userMapper.toDto(updatedUser);
        return ResponseEntity.ok(updatedUserDto);
    }

    /**
     * Update last login information
     * @param id User ID
     * @param request Request containing lastLoginIp
     * @return Updated user DTO
     */
    @PostMapping("/{id}/update-login")
    public ResponseEntity<UserDTO> updateLastLogin(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<User> userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userOpt.get();
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(request.get("lastLoginIp"));
        user.setFailedLoginAttempts(0);
        
        User updatedUser = userRepository.save(user);
        UserDTO updatedUserDto = userMapper.toDto(updatedUser);
        return ResponseEntity.ok(updatedUserDto);
    }

    /**
     * Get user statistics
     * @return Map containing various user statistics
     */
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

    /**
     * Get recent users (created in last 30 days)
     * @return List of user DTOs created in the last 30 days
     */
    @GetMapping("/recent")
    public ResponseEntity<List<UserDTO>> getRecentUsers() {
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
        List<User> users = userRepository.findByCreatedAtAfter(thirtyDaysAgo);
        List<UserDTO> userDtos = users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }
} 
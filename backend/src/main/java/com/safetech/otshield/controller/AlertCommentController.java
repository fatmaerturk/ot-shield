package com.safetech.otshield.controller;

import com.safetech.otshield.dto.AlertCommentDTO;
import com.safetech.otshield.mapper.AlertCommentMapper;
import com.safetech.otshield.model.Alert;
import com.safetech.otshield.mapper.AlertComment;
import com.safetech.otshield.repository.AlertCommentRepository;
import com.safetech.otshield.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST Controller for managing alert comments
 * Provides CRUD operations and comment management capabilities for alert collaboration
 */
@RestController
@RequestMapping("/api/alert-comments")
@RequiredArgsConstructor
public class AlertCommentController {

    private final AlertCommentRepository alertCommentRepository;
    private final AlertRepository alertRepository;
    private final AlertCommentMapper alertCommentMapper;

    /**
     * Get all comments with pagination and sorting
     */
    @GetMapping
    public ResponseEntity<Page<AlertCommentDTO>> getAllComments(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {
        
        Sort sort = sortDir.equalsIgnoreCase("ASC") ? 
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<AlertComment> comments = alertCommentRepository.findAll(pageable);
        Page<AlertCommentDTO> commentDtos = comments.map(alertCommentMapper::toDto);
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get comment by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<AlertCommentDTO> getCommentById(@PathVariable String id) {
        Optional<AlertComment> comment = alertCommentRepository.findById(id);
        return comment.map(alertCommentMapper::toDto)
                     .map(ResponseEntity::ok)
                     .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new comment
     */
    @PostMapping
    public ResponseEntity<AlertCommentDTO> createComment(@RequestBody AlertCommentDTO commentDto) {
        if (!alertRepository.existsById(commentDto.getAlertId())) {
            return ResponseEntity.badRequest().build();
        }
        
        AlertComment comment = alertCommentMapper.toEntity(commentDto);
        // Set the alert reference
        Alert alert = alertRepository.findById(commentDto.getAlertId()).orElse(null);
        comment.setAlert(alert);
        
        AlertComment savedComment = alertCommentRepository.save(comment);
        AlertCommentDTO savedCommentDto = alertCommentMapper.toDto(savedComment);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedCommentDto);
    }

    /**
     * Update an existing comment
     */
    @PutMapping("/{id}")
    public ResponseEntity<AlertCommentDTO> updateComment(@PathVariable String id, @RequestBody AlertCommentDTO commentDto) {
        if (!alertCommentRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        AlertComment comment = alertCommentMapper.toEntity(commentDto);
        comment.setId(id);
        AlertComment updatedComment = alertCommentRepository.save(comment);
        AlertCommentDTO updatedCommentDto = alertCommentMapper.toDto(updatedComment);
        return ResponseEntity.ok(updatedCommentDto);
    }

    /**
     * Delete a comment
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteComment(@PathVariable String id) {
        if (!alertCommentRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        alertCommentRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Get all comments for a specific alert
     */
    @GetMapping("/alert/{alertId}")
    public ResponseEntity<Page<AlertCommentDTO>> getCommentsByAlertId(
            @PathVariable String alertId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<AlertComment> comments = alertCommentRepository.findByAlertId(alertId, pageable);
        Page<AlertCommentDTO> commentDtos = comments.map(alertCommentMapper::toDto);
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get all comments by a specific user
     */
    @GetMapping("/user/{createdBy}")
    public ResponseEntity<List<AlertCommentDTO>> getCommentsByUser(@PathVariable String createdBy) {
        List<AlertComment> comments = alertCommentRepository.findByCreatedBy(createdBy);
        List<AlertCommentDTO> commentDtos = comments.stream()
                .map(alertCommentMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get internal comments only
     */
    @GetMapping("/internal")
    public ResponseEntity<List<AlertCommentDTO>> getInternalComments() {
        List<AlertComment> comments = alertCommentRepository.findByIsInternalTrue();
        List<AlertCommentDTO> commentDtos = comments.stream()
                .map(alertCommentMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get external comments only
     */
    @GetMapping("/external")
    public ResponseEntity<List<AlertCommentDTO>> getExternalComments() {
        List<AlertComment> comments = alertCommentRepository.findByIsInternalFalse();
        List<AlertCommentDTO> commentDtos = comments.stream()
                .map(alertCommentMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get comments by type
     */
    @GetMapping("/type/{commentType}")
    public ResponseEntity<List<AlertCommentDTO>> getCommentsByType(@PathVariable AlertComment.CommentType commentType) {
        List<AlertComment> comments = alertCommentRepository.findByCommentType(commentType);
        List<AlertCommentDTO> commentDtos = comments.stream()
                .map(alertCommentMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Search comments by text content
     */
    @GetMapping("/search")
    public ResponseEntity<Page<AlertCommentDTO>> searchComments(
            @RequestParam String searchTerm,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<AlertComment> comments = alertCommentRepository.searchComments(searchTerm, pageable);
        Page<AlertCommentDTO> commentDtos = comments.map(alertCommentMapper::toDto);
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get latest comments for an alert
     */
    @GetMapping("/alert/{alertId}/latest")
    public ResponseEntity<List<AlertCommentDTO>> getLatestCommentsByAlertId(
            @PathVariable String alertId,
            @RequestParam(defaultValue = "10") int limit) {
        
        Pageable pageable = PageRequest.of(0, limit, Sort.by("createdAt").descending());
        List<AlertComment> comments = alertCommentRepository.findLatestCommentsByAlertId(alertId, pageable);
        List<AlertCommentDTO> commentDtos = comments.stream()
                .map(alertCommentMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Get comments with attachments
     */
    @GetMapping("/with-attachments")
    public ResponseEntity<List<AlertCommentDTO>> getCommentsWithAttachments() {
        List<AlertComment> comments = alertCommentRepository.findByAttachmentsIsNotNull();
        List<AlertCommentDTO> commentDtos = comments.stream()
                .map(alertCommentMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(commentDtos);
    }

    /**
     * Add a quick comment to an alert
     */
    @PostMapping("/alert/{alertId}/quick")
    public ResponseEntity<AlertCommentDTO> addQuickComment(
            @PathVariable String alertId,
            @RequestBody Map<String, String> request) {
        
        Optional<Alert> alertOpt = alertRepository.findById(alertId);
        if (alertOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AlertComment comment = AlertComment.builder()
                .alert(alertOpt.get())
                .commentText(request.get("commentText"))
                .createdBy(request.get("createdBy"))
                .isInternal(Boolean.parseBoolean(request.getOrDefault("isInternal", "false")))
                .commentType(AlertComment.CommentType.valueOf(request.getOrDefault("commentType", "GENERAL")))
                .build();
        
        AlertComment savedComment = alertCommentRepository.save(comment);
        AlertCommentDTO savedCommentDto = alertCommentMapper.toDto(savedComment);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedCommentDto);
    }

    /**
     * Get comment statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getCommentStatistics() {
        Map<String, Object> stats = Map.of(
            "totalComments", alertCommentRepository.count(),
            "internalComments", alertCommentRepository.countByIsInternal(true),
            "externalComments", alertCommentRepository.countByIsInternal(false)
        );
        
        return ResponseEntity.ok(stats);
    }
} 
package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AlertCommentDTO;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for AlertComment entity to AlertCommentDTO conversion
 */
@Mapper(componentModel = "spring")
public interface AlertCommentMapper {
    
    AlertCommentMapper INSTANCE = Mappers.getMapper(AlertCommentMapper.class);

    /**
     * Convert AlertComment entity to AlertCommentDTO
     * Maps alert.id to alertId for DTO
     */
    @Mapping(target = "alertId", source = "alert.id")
    AlertCommentDTO toDto(AlertComment alertComment);
    
    /**
     * Convert AlertCommentDTO to AlertComment entity
     * Alert must be set manually in controller
     */
    AlertComment toEntity(AlertCommentDTO dto);
    
    /**
     * Convert list of AlertComment entities to list of AlertCommentDTOs
     */
    List<AlertCommentDTO> toDtoList(List<AlertComment> alertComments);
    
    /**
     * Convert list of AlertCommentDTOs to list of AlertComment entities
     */
    List<AlertComment> toEntityList(List<AlertCommentDTO> dtos);
} 
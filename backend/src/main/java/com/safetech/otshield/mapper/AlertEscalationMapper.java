package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AlertEscalationDTO;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for AlertEscalation entity to AlertEscalationDTO conversion
 */
@Mapper(componentModel = "spring")
public interface AlertEscalationMapper {
    
    AlertEscalationMapper INSTANCE = Mappers.getMapper(AlertEscalationMapper.class);

    /**
     * Convert AlertEscalation entity to AlertEscalationDTO
     * Maps alert.id to alertId for DTO
     */
    @Mapping(target = "alertId", source = "alert.id")
    AlertEscalationDTO toDto(AlertEscalation alertEscalation);
    
    /**
     * Convert AlertEscalationDTO to AlertEscalation entity
     * Alert must be set manually in controller
     */
    AlertEscalation toEntity(AlertEscalationDTO dto);
    
    /**
     * Convert list of AlertEscalation entities to list of AlertEscalationDTOs
     */
    List<AlertEscalationDTO> toDtoList(List<AlertEscalation> alertEscalations);
    
    /**
     * Convert list of AlertEscalationDTOs to list of AlertEscalation entities
     */
    List<AlertEscalation> toEntityList(List<AlertEscalationDTO> dtos);
} 
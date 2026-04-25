package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AlertRuleDTO;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for AlertRule entity to AlertRuleDTO conversion
 */
@Mapper(componentModel = "spring")
public interface AlertRuleMapper {
    
    AlertRuleMapper INSTANCE = Mappers.getMapper(AlertRuleMapper.class);

    /**
     * Convert AlertRule entity to AlertRuleDTO
     */
    AlertRuleDTO toDto(AlertRule alertRule);
    
    /**
     * Convert AlertRuleDTO to AlertRule entity
     */
    AlertRule toEntity(AlertRuleDTO dto);
    
    /**
     * Convert list of AlertRule entities to list of AlertRuleDTOs
     */
    List<AlertRuleDTO> toDtoList(List<AlertRule> alertRules);
    
    /**
     * Convert list of AlertRuleDTOs to list of AlertRule entities
     */
    List<AlertRule> toEntityList(List<AlertRuleDTO> dtos);
} 
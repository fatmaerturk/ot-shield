package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AlertDTO;
import com.safetech.otshield.model.Alert;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for Alert entity to AlertDTO conversion
 */
@Mapper(componentModel = "spring")
public interface AlertMapper {

    AlertMapper INSTANCE = Mappers.getMapper(AlertMapper.class);

    /**
     * Convert Alert entity to AlertDTO. Populates the legacy `timestamp`
     * field from `createdAt` so older frontend code that reads
     * `alert.timestamp` keeps rendering the detection time correctly.
     */
    @Mapping(target = "timestamp", source = "createdAt")
    AlertDTO toDto(Alert alert);
    
    /**
     * Convert AlertDTO to Alert entity
     */
    Alert toEntity(AlertDTO alertDto);
    
    /**
     * Convert list of Alert entities to list of AlertDTOs
     */
    List<AlertDTO> toDtoList(List<Alert> alerts);
    
    /**
     * Convert list of AlertDTOs to list of Alert entities
     */
    List<Alert> toEntityList(List<AlertDTO> alertDtos);
} 
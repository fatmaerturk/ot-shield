package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AlertNotificationDTO;
import com.safetech.otshield.model.AlertNotification;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for AlertNotification entity to AlertNotificationDTO conversion
 */
@Mapper(componentModel = "spring")
public interface AlertNotificationMapper {
    
    AlertNotificationMapper INSTANCE = Mappers.getMapper(AlertNotificationMapper.class);

    /**
     * Convert AlertNotification entity to AlertNotificationDTO
     * Maps alert.id to alertId for DTO
     */
    @Mapping(target = "alertId", source = "alert.id")
    AlertNotificationDTO toDto(AlertNotification alertNotification);
    
    /**
     * Convert AlertNotificationDTO to AlertNotification entity
     * Alert must be set manually in controller
     */
    AlertNotification toEntity(AlertNotificationDTO dto);
    
    /**
     * Convert list of AlertNotification entities to list of AlertNotificationDTOs
     */
    List<AlertNotificationDTO> toDtoList(List<AlertNotification> alertNotifications);
    
    /**
     * Convert list of AlertNotificationDTOs to list of AlertNotification entities
     */
    List<AlertNotification> toEntityList(List<AlertNotificationDTO> dtos);
} 
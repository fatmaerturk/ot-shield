package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

@Mapper(componentModel = "spring")
public interface AnomalyMapper {
    AnomalyMapper INSTANCE = Mappers.getMapper(AnomalyMapper.class);

    AnomalyDTO toDto(Anomaly anomaly);
    Anomaly toEntity(AnomalyDTO anomalyDto);
    List<AnomalyDTO> toDtoList(List<Anomaly> anomalies);
    List<Anomaly> toEntityList(List<AnomalyDTO> anomalyDtos);
} 
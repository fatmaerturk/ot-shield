package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.AssetDTO;
import com.safetech.otshield.model.Asset;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for Asset entity to AssetDTO conversion
 */
@Mapper(componentModel = "spring")
public interface AssetMapper {
    
    AssetMapper INSTANCE = Mappers.getMapper(AssetMapper.class);
    
    /**
     * Convert Asset entity to AssetDTO
     */
    AssetDTO toDto(Asset asset);
    
    /**
     * Convert AssetDTO to Asset entity
     */
    Asset toEntity(AssetDTO assetDto);
    
    /**
     * Convert list of Asset entities to list of AssetDTOs
     */
    List<AssetDTO> toDtoList(List<Asset> assets);
    
    /**
     * Convert list of AssetDTOs to list of Asset entities
     */
    List<Asset> toEntityList(List<AssetDTO> assetDtos);
} 
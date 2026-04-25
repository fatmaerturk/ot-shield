package com.safetech.otshield.mapper;

import com.safetech.otshield.dto.UserDTO;
import com.safetech.otshield.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * MapStruct mapper for User entity to UserDTO conversion
 * Password field is automatically excluded since it's not in UserDTO
 */
@Mapper(componentModel = "spring")
public interface UserMapper {
    
    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);
    
    /**
     * Convert User entity to UserDTO
     * Password field is automatically excluded since it's not in UserDTO
     */
    UserDTO toDto(User user);
    
    /**
     * Convert UserDTO to User entity
     * Password field is ignored as it should be handled separately
     */
    User toEntity(UserDTO userDto);
    
    /**
     * Convert list of User entities to list of UserDTOs
     */
    List<UserDTO> toDtoList(List<User> users);
    
    /**
     * Convert list of UserDTOs to list of User entities
     */
    List<User> toEntityList(List<UserDTO> userDtos);
} 
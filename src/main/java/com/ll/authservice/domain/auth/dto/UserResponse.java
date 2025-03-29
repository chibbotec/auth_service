package com.ll.authservice.domain.auth.dto;

import com.ll.authservice.domain.auth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
  private Long id;
  private String username;

  public static UserResponse from(User user) {
    return UserResponse.builder()
        .id(user.getId())
        .username(user.getUsername())
        .build();
  }
}
package com.ll.authservice.domain.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
  @NotBlank(message = "사용자 이름은 필수입니다")
  private String username;

  @NotBlank(message = "비밀번호는 필수입니다")
  private String password;
}

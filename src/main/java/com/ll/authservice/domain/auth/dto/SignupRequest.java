package com.ll.authservice.domain.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {

  @NotBlank(message = "사용자명은 필수입니다")
  @Size(min = 3, max = 50, message = "사용자명은 3자 이상 50자 이하여야 합니다")
  private String username;

  @NotBlank(message = "비밀번호는 필수입니다")
  @Size(min = 4, message = "비밀번호는 4자 이상이어야 합니다")
  private String password;

  // 추가적인 회원 프로필 정보 (Member 서비스로 전달할 정보)
  private String email;
  private String nickname;
}
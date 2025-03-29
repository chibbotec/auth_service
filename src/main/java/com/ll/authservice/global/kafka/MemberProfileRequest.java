package com.ll.authservice.global.kafka;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemberProfileRequest {
  private Long id;
  private String username;  // 인증 서비스의 사용자 이름
  private String email;
  private String nickname;
  // 필요한 추가 프로필 정보
}


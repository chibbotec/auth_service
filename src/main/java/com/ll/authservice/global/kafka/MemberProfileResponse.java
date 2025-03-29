package com.ll.authservice.global.kafka;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemberProfileResponse {
  private Long id;          // 회원 서비스의 사용자 ID
  private String username;
  private String email;
  private String nickname;
  // 필요한 추가 프로필 정보
}

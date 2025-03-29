package com.ll.authservice.domain.auth.service;

import com.ll.authservice.domain.auth.dto.LoginRequest;
import com.ll.authservice.domain.auth.dto.SignupRequest;
import com.ll.authservice.domain.auth.dto.TokenResponse;
import com.ll.authservice.domain.auth.dto.UserResponse;
import com.ll.authservice.domain.auth.entity.User;
import com.ll.authservice.domain.auth.jwt.JwtProvider;
import com.ll.authservice.domain.auth.repository.UserRepository;
import com.ll.authservice.global.enums.Topics;
import com.ll.authservice.global.error.ErrorCode;
import com.ll.authservice.global.exception.CustomException;
import com.ll.authservice.global.kafka.MemberProfileRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtProvider jwtProvider;
  private final KafkaTemplate<String, Object> kafkaTemplate;

  @Transactional
  public UserResponse signup(SignupRequest request) {
    // 이미 존재하는 사용자인지 확인
    if (userRepository.findByUsername(request.getUsername()).isPresent()) {
      throw new CustomException(ErrorCode.DUPLICATE_USER);
    }

    // 1. Auth 서비스에 사용자 저장
    User user = User.builder()
        .username(request.getUsername())
        .password(passwordEncoder.encode(request.getPassword()))
        .build();

    User savedUser = userRepository.save(user);

    // 2. Member 서비스에 프로필 정보 전달
    MemberProfileRequest profileRequest = MemberProfileRequest.builder()
        .id(savedUser.getId())
        .username(savedUser.getUsername())
        .email(request.getEmail())
        .nickname(request.getNickname())
        .build();

    kafkaTemplate.send(Topics.SIGNUP.getTopicName(), profileRequest);

    // 응답 생성
    return UserResponse.builder()
        .id(savedUser.getId())
        .username(savedUser.getUsername())
        .build();
  }

  @Transactional
  public TokenResponse login(LoginRequest request) {
    // 사용자 찾기
    User user = userRepository.findByUsername(request.getUsername())
        .orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_USER));

    // 비밀번호 검증
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
      throw new CustomException(ErrorCode.INVALID_TOKEN);
    }

    // 토큰 생성
    String accessToken = jwtProvider.genAccessToken(user);
    String refreshToken = jwtProvider.genRefreshToken(user);

    // 사용자에 리프레시 토큰 저장
    user.setRefreshToken(refreshToken);
    userRepository.save(user);

    // 응답 생성
    return TokenResponse.builder()
        .username(user.getUsername())
        .accessToken(accessToken)
        .refreshToken(refreshToken)
        .accessTokenExpirationTime(3600) // 초 단위
        .build();
  }

  @Transactional
  public TokenResponse refreshToken(String refreshToken) {
    // 리프레시 토큰으로 사용자 찾기
    User user = userRepository.findByRefreshToken(refreshToken)
        .orElseThrow(() -> new CustomException(ErrorCode.INVALID_REFRESH_TOKEN));

    // 리프레시 토큰 검증
    if (!jwtProvider.verify(refreshToken)) {
      throw new CustomException(ErrorCode.INVALID_TOKEN);
    }

    // 새 액세스 토큰 생성
    String newAccessToken = jwtProvider.genAccessToken(user);

    // 새 리프레시 토큰 생성 (선택적 - 보안 강화를 위해 리프레시 토큰도 갱신할 수 있음)
    String newRefreshToken = jwtProvider.genRefreshToken(user);
    user.setRefreshToken(newRefreshToken);
    userRepository.save(user);

    return TokenResponse.builder()
        .username(user.getUsername())
        .accessToken(newAccessToken)
        .refreshToken(newRefreshToken)
        .accessTokenExpirationTime(3600) // 초 단위
        .build();
  }

  @Transactional(readOnly = true)
  public UserResponse getUserProfile(String username) {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_USER));

    return UserResponse.from(user);
  }

  @Transactional
  public void logout(String refreshToken) {
    // 리프레시 토큰으로 사용자 찾기
    userRepository.findByRefreshToken(refreshToken)
        .ifPresent(user -> {
          // 리프레시 토큰 무효화
          user.setRefreshToken(null);
          userRepository.save(user);
        });
    // 사용자를 찾지 못하더라도 로그아웃은 항상 성공으로 간주
  }

  public User findByUsername(String username){
    return userRepository.findByUsername(username).orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_USER));
  }

  public User saveUser(User user) {

    String refreshToken = jwtProvider.genRefreshToken(user);

    // 사용자에 리프레시 토큰 저장
    user.setRefreshToken(refreshToken);

    User savedUser = userRepository.save(user);



    MemberProfileRequest profileRequest = MemberProfileRequest.builder()
        .id(savedUser.getId())
        .username(savedUser.getUsername())
        .build();
    kafkaTemplate.send(Topics.SIGNUP.getTopicName(), profileRequest);
    return savedUser;
  }
}

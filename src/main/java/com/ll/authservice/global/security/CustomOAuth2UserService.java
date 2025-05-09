package com.ll.authservice.global.security;

import jakarta.transaction.Transactional;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
  @Transactional
  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) {
    OAuth2User oAuth2User = super.loadUser(userRequest);
    String oauthId = oAuth2User.getName();
    String providerTypeCode = userRequest
        .getClientRegistration()
        .getRegistrationId()
        .toUpperCase(Locale.getDefault());

    // 요청 스코프 정보 추출
    String scopes = userRequest.getClientRegistration().getScopes()
        .stream()
        .collect(Collectors.joining(","));
    log.debug("OAuth2 요청 스코프: {}", scopes);

    // OAuth2 액세스 토큰 및 만료 정보 추출
    OAuth2AccessToken accessToken = userRequest.getAccessToken();
    String tokenValue = accessToken.getTokenValue();

    Map<String, Object> attributes = oAuth2User.getAttributes();

    // 디버그용 로그
    log.debug("OAuth2 사용자 정보: {}", attributes);

    // GitHub 사용자 정보 추출
    String nickname = (String) attributes.get("nickname"); // 사용자가 설정한 이름
    if (nickname == null || nickname.isEmpty()) {
      nickname = (String) attributes.get("login"); // 이름이 없으면 로그인 아이디 사용
    }
    String email = (String) attributes.get("email");
    String githubUsername = (String) attributes.get("login"); // GitHub 로그인 아이디

    // 사용자명 생성 (GitHub__123456 형태)
    String username = providerTypeCode + "__" + oauthId;

    log.info("OAuth2 로그인 정보: provider={}, id={}, username={}, nickname={}, email={}, githubUsername={}",
        providerTypeCode, oauthId, username, nickname, email, githubUsername);

    return new SecurityUser(
        0L,
        username,
        "",
        nickname,
        email,
        List.of(),
        githubUsername,
        tokenValue,
        scopes,
        providerTypeCode,
        oauthId
    );
  }
}
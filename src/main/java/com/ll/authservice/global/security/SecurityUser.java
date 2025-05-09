package com.ll.authservice.global.security;

import java.util.Collection;
import java.util.Map;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class SecurityUser extends User implements OAuth2User {
  @Getter
  private long id;
  @Getter
  private String nickname;
  @Getter
  private String email;

  // GitHub 관련 추가 정보
  @Getter
  private String githubUsername;
  @Getter
  private String githubAccessToken;
  @Getter
  private String githubScopes;
  @Getter
  private String providerType;
  @Getter
  private String providerId;

  public SecurityUser(
      long id,
      String username,
      String password,
      String nickname,
      String email,
      Collection<? extends GrantedAuthority> authorities
  ) {
    super(username, password, authorities);
    this.id = id;
    this.nickname = nickname;
    this.email = email;
  }

  public SecurityUser(
      long id,
      String username,
      String password,
      String nickname,
      String email,
      Collection<? extends GrantedAuthority> authorities,
      String githubUsername,
      String githubAccessToken,
      String githubScopes,
      String providerType,
      String providerId
  ) {
    super(username, password, authorities);
    this.id = id;
    this.nickname = nickname;
    this.email = email;
    this.githubUsername = githubUsername;
    this.githubAccessToken = githubAccessToken;
    this.githubScopes = githubScopes;
    this.providerType = providerType;
    this.providerId = providerId;
  }

  @Override
  public Map<String, Object> getAttributes() {
    return Map.of(
        "id", id,
        "username", getUsername(),
        "nickname", nickname,
        "email", email,
        "githubUsername", githubUsername,
        "providerType", providerType,
        "providerId", providerId
    );
  }

  @Override
  public String getName() {
    return getUsername();
  }
}
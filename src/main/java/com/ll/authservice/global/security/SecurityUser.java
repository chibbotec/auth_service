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
  }

  @Override
  public Map<String, Object> getAttributes() {
    return Map.of();
  }

  @Override
  public String getName() {
    return getUsername();
  }
}

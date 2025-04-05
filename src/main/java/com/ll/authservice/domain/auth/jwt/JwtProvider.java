package com.ll.authservice.domain.auth.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ll.authservice.domain.auth.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtProvider {

  @Value("${custom.jwt.secretKey}") private String secretKeyOrigin;
  @Value("${custom.accessToken.expirationSeconds}") private int accessTokenExpirationSeconds;
  @Value("${custom.refreshToken.expirationSeconds}") private int refreshTokenExpirationSeconds;

  private SecretKey cachedSecretKey;
  private ObjectMapper objectMapper = new ObjectMapper();

  public SecretKey getSecretKey() {
    if (cachedSecretKey == null) {
      cachedSecretKey = cachedSecretKey = _getSecretKey();
    }
    return cachedSecretKey;
  }

  private SecretKey _getSecretKey() {
    String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyOrigin.getBytes());
    return Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
  }

  public String genAccessToken(User user) {
    return genToken(user, accessTokenExpirationSeconds);
  }

  public String genRefreshToken(User user) {
    return genToken(user, refreshTokenExpirationSeconds);
  }

  private String genToken(User user, int expirationSeconds) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("id", user.getId());
    claims.put("username", user.getUsername());
    claims.put("sessionId", UUID.randomUUID().toString()); // 고유 세션 ID 추가

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + 1000L * expirationSeconds);

    try {
      String claimsJson = objectMapper.writeValueAsString(claims);

      return Jwts.builder()
          .claim("body", claimsJson)
          .setIssuedAt(now)
          .setExpiration(expiryDate)
          .signWith(getSecretKey(), SignatureAlgorithm.HS512)
          .compact();
    } catch (JsonProcessingException e) {
      log.error("JSON 직렬화 오류", e);
      throw new RuntimeException("토큰 생성 중 오류가 발생했습니다", e);
    }
  }

  public boolean verify(String token) {
    try {
      Jwts.parserBuilder()
          .setSigningKey(getSecretKey())
          .build()
          .parseClaimsJws(token);
      return true;
    } catch (Exception e) {
      log.error("토큰 검증 오류", e);
      return false;
    }
  }

  public int getAccessTokenExpirationTime() {
    return accessTokenExpirationSeconds;
  }

  public int getRefreshTokenExpirationTime() {
    return refreshTokenExpirationSeconds;
  }
}

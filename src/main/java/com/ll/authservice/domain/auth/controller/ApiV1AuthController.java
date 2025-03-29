package com.ll.authservice.domain.auth.controller;

import com.ll.authservice.domain.auth.dto.LoginRequest;
import com.ll.authservice.domain.auth.dto.RefreshTokenRequest;
import com.ll.authservice.domain.auth.dto.SignupRequest;
import com.ll.authservice.domain.auth.dto.TokenResponse;
import com.ll.authservice.domain.auth.dto.UserResponse;
import com.ll.authservice.domain.auth.service.AuthService;
import com.ll.authservice.global.rq.Rq;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import java.util.Iterator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class ApiV1AuthController {

  private final AuthService authService;
  private final Rq rq;

  @PostMapping("/signup")
  public ResponseEntity<UserResponse> signup(@Valid @RequestBody SignupRequest signupRequest) {
    UserResponse userResponse = authService.signup(signupRequest);
    return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
  }

  @PostMapping("/login")
  public ResponseEntity<TokenResponse> login(
      @Valid @RequestBody LoginRequest loginRequest,
      HttpServletResponse response) {

    TokenResponse tokenResponse = authService.login(loginRequest);

    // 쿠키에 토큰 설정
    addTokenCookies(response, tokenResponse);

    return ResponseEntity.ok(tokenResponse);
  }

  @PostMapping("/refresh")
  public ResponseEntity<TokenResponse> refreshToken(
      @CookieValue(value = "refreshToken", required = false) String cookieRefreshToken,
      @RequestBody(required = false) RefreshTokenRequest requestRefreshToken,
      HttpServletResponse response) {

    // 쿠키 또는 요청 본문에서 리프레시 토큰 가져오기
    String refreshToken = cookieRefreshToken;
    if (refreshToken == null && requestRefreshToken != null) {
      refreshToken = requestRefreshToken.getRefreshToken();
    }

    if (refreshToken == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

    TokenResponse tokenResponse = authService.refreshToken(refreshToken);

    // 쿠키에 새 토큰 설정
    addTokenCookies(response, tokenResponse);

    return ResponseEntity.ok(tokenResponse);
  }

  @GetMapping("/logout")
  public ResponseEntity<Void> logout(
      @CookieValue(value = "refreshToken", required = false) String refreshToken,
      HttpServletResponse response) {

    if (refreshToken != null) {
      authService.logout(refreshToken);
    }

    // 토큰 쿠키 삭제
    removeTokenCookies(response);

    return ResponseEntity.ok().build();
  }

  @GetMapping("/user")
  public ResponseEntity<UserResponse> getUserProfile(
      @RequestHeader("X-Username") String username) {

    UserResponse userResponse = authService.getUserProfile(username);
    return ResponseEntity.ok(userResponse);
  }

  @GetMapping("/session")
  @ResponseBody
  public String session(HttpSession session) {
    String sessionDump = Stream.iterate(
            session.getAttributeNames().asIterator(),
            Iterator::hasNext,
            it -> it
        ).flatMap(it -> Stream.of(it.next()))
        .map(attributeName -> {
          Object attributeValue = session.getAttribute(attributeName);
          return attributeName + " = " + attributeValue;
        })
        .collect(Collectors.joining("\n", "Session Attributes:\n", ""));

    // 완성된 세션 정보 반환
    return sessionDump;
  }

  private void addTokenCookies(HttpServletResponse response, TokenResponse tokenResponse) {
    // 액세스 토큰 쿠키
    Cookie accessTokenCookie = new Cookie("accessToken", tokenResponse.getAccessToken());
    accessTokenCookie.setHttpOnly(true);
    accessTokenCookie.setSecure(true);
    accessTokenCookie.setPath("/");
    accessTokenCookie.setMaxAge((int) tokenResponse.getAccessTokenExpirationTime());
    response.addCookie(accessTokenCookie);

    // 리프레시 토큰 쿠키
    Cookie refreshTokenCookie = new Cookie("refreshToken", tokenResponse.getRefreshToken());
    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setSecure(true);
    refreshTokenCookie.setPath("/");
    refreshTokenCookie.setMaxAge(60 * 60 * 24 * 7); // 7일
    response.addCookie(refreshTokenCookie);
  }

  private void removeTokenCookies(HttpServletResponse response) {
    // 액세스 토큰 쿠키 삭제
    Cookie accessTokenCookie = new Cookie("accessToken", null);
    accessTokenCookie.setHttpOnly(true);
    accessTokenCookie.setSecure(true);
    accessTokenCookie.setPath("/");
    accessTokenCookie.setMaxAge(0);
    response.addCookie(accessTokenCookie);

    // 리프레시 토큰 쿠키 삭제
    Cookie refreshTokenCookie = new Cookie("refreshToken", null);
    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setSecure(true);
    refreshTokenCookie.setPath("/");
    refreshTokenCookie.setMaxAge(0);
    response.addCookie(refreshTokenCookie);
  }
}
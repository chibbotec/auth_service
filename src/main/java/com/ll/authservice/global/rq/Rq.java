package com.ll.authservice.global.rq;

import com.ll.authservice.domain.auth.dto.TokenResponse;
import com.ll.authservice.domain.auth.entity.User;
import com.ll.authservice.domain.auth.jwt.JwtProvider;
import com.ll.authservice.global.config.AppConfig;
import com.ll.authservice.global.security.SecurityUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

// Request/Response 를 추상화한 객체
// Request, Response, Cookie, Session 등을 다룬다.
@RequestScope
@Component
@RequiredArgsConstructor
public class Rq {
    private final HttpServletRequest req;
    private final HttpServletResponse resp;
    private final JwtProvider jwtProvider;

    public User getActor() {
        return Optional.ofNullable(
                        SecurityContextHolder
                                .getContext()
                                .getAuthentication()
                )
                .map(Authentication::getPrincipal)
                .filter(principal -> principal instanceof SecurityUser)
                .map(principal -> (SecurityUser) principal)
                .map(securityUser -> new User(securityUser.getId(), securityUser.getUsername()))
                .orElse(null);
    }

    public void setCookie(String name, String value, int maxAgeInSeconds) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
            .path("/")
            .domain(AppConfig.getSiteBackUrl())
            .sameSite("None")
            .secure(true)
            .httpOnly(true)
            .maxAge(maxAgeInSeconds)
            .build();
        resp.addHeader("Set-Cookie", cookie.toString());
    }

    public void setHeader(String name, String value) {
        resp.setHeader(name, value);
    }

    // 토큰 쿠키 설정 (로그인, 리프레시 등)
    public TokenResponse setAuthCookies(User user, String accessToken, String refreshToken) {
        int accessTokenExpirationTime = jwtProvider.getAccessTokenExpirationTime();
        int refreshTokenExpirationTime = jwtProvider.getRefreshTokenExpirationTime();

        // 액세스 토큰 쿠키 설정
        setCookie("accessToken", accessToken, accessTokenExpirationTime);

        // 리프레시 토큰 쿠키 설정
        setCookie("refreshToken", refreshToken, refreshTokenExpirationTime);

        return TokenResponse.builder()
            .username(user.getUsername())
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .accessTokenExpirationTime(accessTokenExpirationTime)
            .build();
    }

    // OAuth2 인증용 메서드 (토큰 생성 + 쿠키 설정)
    public TokenResponse makeAuthCookies(User user) {
        String accessToken = jwtProvider.genAccessToken(user);
        String refreshToken = user.getRefreshToken();

        return setAuthCookies(user, accessToken, refreshToken);
    }

    // 토큰 쿠키 삭제 (로그아웃)
    public void removeAuthCookies() {
        setCookie("accessToken", null, 0);
        setCookie("refreshToken", null, 0);
    }
}
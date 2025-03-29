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
//    private final AuthService authService;

//    public void setLogin(Member member) {
//        UserDetails user = new SecurityUser(
//                member.getId(),
//                member.getUsername(),
//                "",
//                member.getNickname(),
//                member.getAuthorities()
//        );
//
//        Authentication authentication = new UsernamePasswordAuthenticationToken(
//                user,
//                user.getPassword(),
//                user.getAuthorities()
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//    }

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

//    public void setCookie(String name, String value) {
//        ResponseCookie cookie = ResponseCookie.from(name, value)
//                .path("/")
//                .domain(AppConfig.getSiteBackUrl())
//                .sameSite("Strict")
//                .secure(true)
//                .httpOnly(true)
////                .httpOnly(false)
//                .build();
//        resp.addHeader("Set-Cookie", cookie.toString());
//    }

    public void setCookie(String name, String value, int maxAgeInSeconds) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
            .path("/")
            .domain(AppConfig.getSiteBackUrl())
            .sameSite("Strict")
            .secure(true)
            .httpOnly(true)
            .maxAge(maxAgeInSeconds)
            .build();
        resp.addHeader("Set-Cookie", cookie.toString());
    }

//    public String getCookieValue(String name) {
//        return Optional
//                .ofNullable(req.getCookies())
//                .stream() // 1 ~ 0
//                .flatMap(cookies -> Arrays.stream(cookies))
//                .filter(cookie -> cookie.getName().equals(name))
//                .map(cookie -> cookie.getValue())
//                .findFirst()
//                .orElse(null);
//    }
//
//    public void deleteCookie(String name) {
//        ResponseCookie cookie = ResponseCookie.from(name, null)
//                .path("/")
//                .domain(AppConfig.getSiteBackUrl())
//                .sameSite("Strict")
//                .secure(true)
//                .httpOnly(true)
//                .maxAge(0)
//                .build();
//
//        resp.addHeader("Set-Cookie", cookie.toString());
//    }

    public void setHeader(String name, String value) {
        resp.setHeader(name, value);
    }

//    public String getHeader(String name) {
//        return req.getHeader(name);
//    }
//
//    public void refreshAccessToken(Member member) {
//        String newAccessToken = memberService.genAccessToken(member);
//
//        setHeader("Authorization", "Bearer " + member.getApiKey() + " " + newAccessToken);
//        setCookie("accessToken", newAccessToken);
//    }

    // OAuth2 인증 성공 후 토큰 쿠키 설정 메서드 수정
    public TokenResponse makeAuthCookies(User user) {
        // JwtProvider를 통해 액세스 토큰과 리프레시 토큰 생성
        String accessToken = jwtProvider.genAccessToken(user);
        String refreshToken = user.getRefreshToken();

        // 토큰 만료 시간 가져오기
        int accessTokenExpirationTime = jwtProvider.getAccessTokenExpirationTime();
        int refreshTokenExpirationTime = jwtProvider.getRefreshTokenExpirationTime();

        // 액세스 토큰 쿠키 설정
        setCookie("accessToken", accessToken, accessTokenExpirationTime);

        // 리프레시 토큰 쿠키 설정 (7일)
        setCookie("refreshToken", refreshToken, refreshTokenExpirationTime);

        // TokenResponse 객체 생성하여 반환
        return TokenResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .accessTokenExpirationTime(accessTokenExpirationTime)
            .build();
    }
}
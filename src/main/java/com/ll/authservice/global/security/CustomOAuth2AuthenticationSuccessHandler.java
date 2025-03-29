package com.ll.authservice.global.security;


import com.ll.authservice.domain.auth.entity.User;
import com.ll.authservice.domain.auth.service.AuthService;
import com.ll.authservice.global.rq.Rq;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final AuthService authService;
    private final Rq rq;

    @SneakyThrows
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.info("OAuth2 로그인 성공: {}", authentication.getName());

        // SecurityUser에서 사용자 정보 가져오기
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();

        // 사용자가 DB에 존재하는지 확인하고, 없으면 새로 생성
        User user;

        try {
            // 기존 사용자 검색 (username으로)
            user = authService.findByUsername(securityUser.getUsername());
        } catch (Exception e) {
            // 사용자가 없으면 새로 생성
            log.info("새 소셜 로그인 사용자 생성: {}", securityUser.getUsername());
            user = User.builder()
                .username(securityUser.getUsername())
                .password("") // 소셜 로그인 사용자는 비밀번호 불필요
                .nickname(securityUser.getUsername())
                .email(securityUser.getEmail())
                .build();
            user = authService.saveUser(user);

        }

        log.info("사용자 정보: {}", user.getUsername());

        // Rq 유틸리티를 사용하여 토큰 쿠키 설정
        rq.makeAuthCookies(user);

        // 리다이렉트 URL 설정 (state 파라미터에서 가져옴)
        String redirectUrl = request.getParameter("state");

//        // 리다이렉트 URL이 없는 경우 기본 URL로 설정
//        if (redirectUrl == null || redirectUrl.isEmpty()) {
//            redirectUrl = "/"; // 기본 URL
//        }

        // 리다이렉트 수행
        response.sendRedirect(redirectUrl);
    }
}
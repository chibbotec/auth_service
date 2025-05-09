package com.ll.authservice.global.security;

import com.ll.authservice.domain.auth.entity.User;
import com.ll.authservice.domain.auth.service.AuthService;
import com.ll.authservice.global.enums.Topics;
import com.ll.authservice.global.kafka.GitHubLoginEvent;
import com.ll.authservice.global.rq.Rq;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final AuthService authService;
    private final Rq rq;
    private final KafkaTemplate<String, Object> kafkaTemplate;

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
            // 기존 사용자의 기본 정보만 업데이트 (필요한 경우)
            // GitHub 관련 정보는 업데이트하지 않음
        } catch (Exception e) {
            // 사용자가 없으면 새로 생성 (기본 정보만)
            log.info("새 소셜 로그인 사용자 생성: {}", securityUser.getUsername());

            user = User.builder()
                .username(securityUser.getUsername())
                .password("") // 소셜 로그인 사용자는 비밀번호 불필요
                .nickname(securityUser.getNickname())
                .email(securityUser.getEmail())
                .build();
        }

        // 사용자 저장 (GitHub 정보 없이)
        user = authService.saveUser(user);

        log.info("사용자 정보: {}", user.getUsername());

        // Rq 유틸리티를 사용하여 토큰 쿠키 설정
        var tokenResponse = rq.makeAuthCookies(user);

        // GitHub 정보가 있으면 Kafka로 전송
        if (securityUser.getGithubUsername() != null) {
            // GitHub 로그인 이벤트를 Kafka로 전파
            GitHubLoginEvent githubLoginEvent = GitHubLoginEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .githubUsername(securityUser.getGithubUsername())
                .githubAccessToken(securityUser.getGithubAccessToken())
//                .githubTokenExpires(LocalDateTime.now().plusHours(1)) // 토큰 만료 시간 설정 (예: 1시간)
                .githubScopes(securityUser.getGithubScopes())
                .build();

            // Kafka로 이벤트 전송
            kafkaTemplate.send(Topics.GITHUB_LOGIN.getTopicName(), githubLoginEvent);
            log.info("GitHub 로그인 이벤트 전송 완료: {}", user.getUsername());
        }

        // 리다이렉트 URL 설정 (state 파라미터에서 가져옴)
        String redirectUrl = request.getParameter("state");

        // 리다이렉트 수행
        response.sendRedirect(redirectUrl);
    }
}
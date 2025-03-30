package com.ll.authservice.global.config;

import com.ll.authservice.global.security.CustomAuthorizationRequestResolver;
import com.ll.authservice.global.security.CustomOAuth2AuthenticationSuccessHandler;
import com.ll.authservice.global.security.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final CustomOAuth2UserService customOAuth2UserService;
  private final CustomOAuth2AuthenticationSuccessHandler customOAuth2AuthenticationSuccessHandler;
  private final CustomAuthorizationRequestResolver authorizationRequestResolver;

//  @Bean
//  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//    http
//        .authorizeHttpRequests(auth -> auth
//            // API 게이트웨이가 이미 인증된 요청만 전달한다고 가정
//            .anyRequest().permitAll()
//        )
//        .csrf(csrf -> csrf.disable())
//        .sessionManagement(session ->
//            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        )
////        .oauth2Login(oauth2Login -> oauth2Login
////            .authorizationEndpoint(authorization -> authorization
////                .baseUri("/oauth2/authorization")
////                .authorizationRequestResolver(authorizationRequestResolver)
////            )
////            .redirectionEndpoint(redirection -> redirection
////                .baseUri("/login/oauth2/code/*")
////            )
////            .userInfoEndpoint(userInfo -> userInfo
////                .userService(customOAuth2UserService)
////            )
////            .successHandler(customOAuth2AuthenticationSuccessHandler)
////        )
//        .oauth2Login(
//            oauth2Login -> oauth2Login
//                .successHandler(customOAuth2AuthenticationSuccessHandler)
//                .authorizationEndpoint(
//                    authorizationEndpoint -> authorizationEndpoint
//                        .authorizationRequestResolver(authorizationRequestResolver)
//                )
//        )
//    ;
//    return http.build();
//  }

  @Bean
  public SecurityFilterChain baseSecurityFilterChain(HttpSecurity http, CustomOAuth2UserService customOAuth2UserService) throws Exception {
    http
        .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    // 나머지 API는 모두 허용 (API 게이트웨이에서 이미 인증됨)
                    .anyRequest().permitAll()
        )
        .headers(
            headers ->
                headers.frameOptions(
                    HeadersConfigurer.FrameOptionsConfig::sameOrigin
                )
        )
        .csrf(AbstractHttpConfigurer::disable)
//        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .formLogin(
            AbstractHttpConfigurer::disable
        )
        .sessionManagement((sessionManagement) -> sessionManagement
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .oauth2Login(
            oauth2Login -> oauth2Login
                .successHandler(customOAuth2AuthenticationSuccessHandler)
                .authorizationEndpoint(
                    authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestResolver(authorizationRequestResolver)
                )
        )
    ;

    return http.build();
  }
}

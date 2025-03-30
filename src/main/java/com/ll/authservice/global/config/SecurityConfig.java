package com.ll.authservice.global.config;

import com.ll.authservice.global.security.CustomAuthorizationRequestResolver;
import com.ll.authservice.global.security.CustomOAuth2AuthenticationSuccessHandler;
import com.ll.authservice.global.security.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final CustomOAuth2UserService customOAuth2UserService;
  private final CustomOAuth2AuthenticationSuccessHandler customOAuth2AuthenticationSuccessHandler;
  private final CustomAuthorizationRequestResolver authorizationRequestResolver;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            // API 게이트웨이가 이미 인증된 요청만 전달한다고 가정
            .anyRequest().permitAll()
        )
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
//        .oauth2Login(oauth2Login -> oauth2Login
//            .authorizationEndpoint(authorization -> authorization
//                .baseUri("/oauth2/authorization")
//                .authorizationRequestResolver(authorizationRequestResolver)
//            )
//            .redirectionEndpoint(redirection -> redirection
//                .baseUri("/login/oauth2/code/*")
//            )
//            .userInfoEndpoint(userInfo -> userInfo
//                .userService(customOAuth2UserService)
//            )
//            .successHandler(customOAuth2AuthenticationSuccessHandler)
//        )
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

//  @Bean
//  public CorsConfigurationSource corsConfigurationSource() {
//    CorsConfiguration configuration = new CorsConfiguration();
//    configuration.setAllowedOrigins(Arrays.asList("*"));
//    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
//    configuration.setAllowCredentials(true);
//
//    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//    source.registerCorsConfiguration("/**", configuration);
//    return source;
//  }
}

package com.example.springoauth.config.security;

import com.example.springoauth.config.binder.CorsProperties;
import com.example.springoauth.config.binder.AuthProperties;
import com.example.springoauth.config.security.filter.JwtAuthenticationFilter;
import com.example.springoauth.config.security.filter.JwtAuthorizationFilter;
import com.example.springoauth.config.security.handler.OAuth2AuthenticationFailureHandler;
import com.example.springoauth.config.security.handler.OAuth2AuthenticationSuccessHandler;
import com.example.springoauth.config.security.oauth.service.CustomOAuth2UserService;
import com.example.springoauth.config.security.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.example.springoauth.config.security.service.PrincipalDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Slf4j
@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final CorsProperties corsProperties;
    private final AuthProperties authProperties;
    private final PrincipalDetailsService principalDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final ApplicationEventPublisher publisher;
    private final ObjectMapper objectMapper;
    private final CustomOAuth2UserService oAuth2UserService;

    /**
     * Spring Security 를 적용하지 않을 리소스
     * */
    @Bean
    public WebSecurityCustomizer configure() {
        return web -> web.ignoring().requestMatchers(
                PathRequest.toH2Console())
                .requestMatchers("/login"
                        , "/api/attach-image"
                        ,"/", "/favicon.ico", "/error")
                ;
    }

    /**
     * 서버에 요청을 할 때 액세스가 가능한지 권한을 체크후 액세스 할 수 없는 요청을 했을시 동작된다
     * */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    /**
     * 인증을 위한 주요 전략 인터페이스
     * */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 인증 처리 과정에서 예외가 발생한 경우 예외를 핸들링하는 인터페이스
     * */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, e) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write(e.getMessage());
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    /**
     * 비밀번화 암호화 인코더
     */
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Cors 설정
     * */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource corsConfigSource = new UrlBasedCorsConfigurationSource();

        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedHeaders(Arrays.asList(corsProperties.getAllowedHeaders().split(",")));
        corsConfig.setAllowedMethods(Arrays.asList(corsProperties.getAllowedMethods().split(",")));
        corsConfig.setAllowedOrigins(Arrays.asList(corsProperties.getAllowedOrigins().split(",")));
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(corsConfig.getMaxAge());

        corsConfigSource.registerCorsConfiguration("/**", corsConfig);
        return corsConfigSource;
    }

    /*
     * 쿠키 기반 인가 Repository
     * 인가 응답을 연계 하고 검증할 때 사용.
     * */
    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    /**
     * Oauth 인증 성공 핸들러
     * */
    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(authProperties, publisher, objectMapper, oAuth2AuthorizationRequestBasedOnCookieRepository());
    }

    /**
     * Oauth 인증 실패 핸들러
     * */
    @Bean
    public OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
        return new OAuth2AuthenticationFailureHandler();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .requestMatchers("/api/login", "/api/users/join"
                ,"/", "/favicon.ico")
                .permitAll()
                .anyRequest().authenticated()
                .and().formLogin().disable()
                .csrf().disable()
                .headers().disable()
                .httpBasic().disable()
                .rememberMe().disable()
//                .logout().logoutUrl("/api/logout").addLogoutHandler(logoutHandler)
//                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK)).permitAll()
//                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler()).
                authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .addFilter(getJwtAuthenticationFilter()).addFilterBefore(getJwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .oauth2Login().loginPage("/login")
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository())
                .and()
                .redirectionEndpoint()
                .baseUri("/*/oauth2/code/*")
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler())
                .failureHandler(oAuth2AuthenticationFailureHandler())
        ;

        return http.build();
    }

    public JwtAuthenticationFilter getJwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(authProperties, publisher, objectMapper);
        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        return filter;
    }

    public JwtAuthorizationFilter getJwtAuthorizationFilter() throws Exception {
        return new JwtAuthorizationFilter(authenticationManager(authenticationConfiguration), authProperties, principalDetailsService, publisher);
    }

}

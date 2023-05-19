package com.example.springoauth.config.security.filter;

import com.example.springoauth.config.binder.AuthProperties;
import com.example.springoauth.config.security.entity.LoginRequest;
import com.example.springoauth.config.security.entity.PrincipalDetails;
import com.example.springoauth.domain.users.event.JwtTokenUpdateEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// User id, password 로그인
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthProperties authProperties;
    private final ApplicationEventPublisher publisher;
    private final ObjectMapper objectMapper;
    public JwtAuthenticationFilter(AuthProperties authProperties, ApplicationEventPublisher publisher, ObjectMapper objectMapper) {
        this.authProperties = authProperties;
        this.publisher = publisher;
        this.objectMapper = objectMapper;
        setFilterProcessesUrl("/api/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("--JWT AUTHENTICATION FILTER--");

        try {
            LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail()
                            , loginRequest.getPassword()
                    ));

        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String loginId = ((PrincipalDetails)authResult.getPrincipal()).getUsername();

        String jwtToken = Jwts.builder()
                .setSubject(loginId)
                .setExpiration(new Date(System.currentTimeMillis() + authProperties.getJwt().getExpiration()))
                .signWith(authProperties.getSecretKey(), SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(loginId)
                .setExpiration(new Date(System.currentTimeMillis() + authProperties.getJwt().getRefreshTokenExpiry()))
                .signWith(authProperties.getSecretKey(), SignatureAlgorithm.HS256)
                .compact();

        publisher.publishEvent(new JwtTokenUpdateEvent(loginId, jwtToken, refreshToken));

        response.addHeader("token", jwtToken);
        Map<String, String> body = new HashMap<>();
        body.put("AccessToken", jwtToken);
        body.put("RefreshToken", refreshToken);
        String bodyStr = objectMapper.writeValueAsString(body);
        response.getWriter().write(bodyStr);
    }
}

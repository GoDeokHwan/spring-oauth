package com.example.springoauth.config.security.filter;

import com.example.springoauth.config.binder.JwtProperties;
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
    private final JwtProperties jwtProperties;
    private final ApplicationEventPublisher publisher;
    private final ObjectMapper objectMapper;
    public JwtAuthenticationFilter(JwtProperties jwtProperties, ApplicationEventPublisher publisher, ObjectMapper objectMapper) {
        this.jwtProperties = jwtProperties;
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
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String loginId = ((PrincipalDetails)authResult.getPrincipal()).getUsername();

        String jwtToken = Jwts.builder()
                .setSubject(loginId)
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpiration()))
                .signWith(jwtProperties.getSecretKey(), SignatureAlgorithm.HS256)
                .compact();

        publisher.publishEvent(new JwtTokenUpdateEvent(loginId, jwtToken));

        response.addHeader("token", jwtToken);
        Map<String, String> body = new HashMap<>();
        body.put("AccessToken", jwtToken);
        String bodyStr = objectMapper.writeValueAsString(body);
        response.getWriter().write(bodyStr);
    }
}

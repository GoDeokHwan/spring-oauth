package com.example.springoauth.config.security.filter;

import com.example.springoauth.config.binder.JwtProperties;
import com.example.springoauth.config.security.entity.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtProperties jwtProperties;
    public JwtAuthenticationFilter(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        setFilterProcessesUrl("/api/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("--JWT AUTHENTICATION FILTER--");

        try {
            LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getLoginId()
                            , loginRequest.getPassword()
                    ));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        String loginId = ((PrincipalDetails)authResult.getPrincipal()).getUsername();
//
//        String jwtToken = Jwts.builder()
//                .setSubject(loginId)
//                .setExpiration(new Date(System.currentTimeMillis() + securityProperties.getExpiration()))
//                .signWith(securityProperties.getSecretKey(), SignatureAlgorithm.HS256)
//                .compact();


//        redisPublisher.publish(RedisTopicContact.getTopic(loginId), jwtToken, RedisTopicContact.getOneHourTime());

//        response.addHeader("token", jwtToken);
//        Map<String, String> body = new HashMap<>();
//        body.put("AccessToken", jwtToken);
//        String bodyStr = objectMapper.writeValueAsString(body);
//        response.getWriter().write(bodyStr);
    }
}

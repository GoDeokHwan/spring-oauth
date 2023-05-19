package com.example.springoauth.config.security.filter;

import com.example.springoauth.config.binder.AuthProperties;
import com.example.springoauth.config.security.entity.PrincipalDetails;
import com.example.springoauth.config.security.service.PrincipalDetailsService;
import com.example.springoauth.domain.users.event.JwtTokenValidationEvent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Date;

/**
 * 토큰 권한 확인 필터
 * */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final AuthProperties authProperties;
    private final PrincipalDetailsService principalDetailsService;
    private final ApplicationEventPublisher publisher;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, AuthProperties authProperties, PrincipalDetailsService principalDetailsService, ApplicationEventPublisher publisher) {
        super(authenticationManager);
        this.authProperties = authProperties;
        this.principalDetailsService = principalDetailsService;
        this.publisher = publisher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            String tokenHeader = request.getHeader("Authorization");
            String jwtToken = null;

            if(StringUtils.hasText(tokenHeader) && tokenHeader.startsWith("Bearer")) {
                jwtToken = tokenHeader.replace("Bearer ", "");
            } else {
                jwtToken = request.getParameterMap().get("token")[0];
            }

            if(jwtToken != null && isValid(jwtToken)) {
                SecurityContextHolder.getContext().setAuthentication(getAuth(jwtToken));
            }

        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }

        chain.doFilter(request, response);
    }

    private Authentication getAuth(String jwtToken) {
        PrincipalDetails user = (PrincipalDetails)principalDetailsService.loadUserByUsername(
                Jwts.parserBuilder()
                        .setSigningKey(authProperties.getSecretKey())
                        .build()
                        .parseClaimsJws(jwtToken).getBody()
                        .getSubject()
        );
        return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
    }

    private boolean isValid(String jwtToken) {
        boolean ret = true;

        Jws<Claims> jws = null;

        try {
            jws = Jwts.parserBuilder()
                    .setSigningKey(authProperties.getSecretKey())
                    .build()
                    .parseClaimsJws(jwtToken);

            if( jws == null ||
                    jws.getBody().getSubject() == null ||
                    jws.getBody().getExpiration().before(new Date())) {
                ret = false;
            }

            publisher.publishEvent(new JwtTokenValidationEvent(jws.getBody().getSubject(), jwtToken));
        } catch (Exception e) {
            ret = false;
        }
        return ret;
    }
}

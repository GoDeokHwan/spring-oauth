package com.example.springoauth.config.security.filter;

import com.example.springoauth.config.binder.JwtProperties;
import com.example.springoauth.config.security.entity.PrincipalDetails;
import com.example.springoauth.config.security.service.PrincipalDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Date;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final JwtProperties jwtProperties;
    private final PrincipalDetailsService principalDetailsService;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtProperties jwtProperties, PrincipalDetailsService principalDetailsService) {
        super(authenticationManager);
        this.jwtProperties = jwtProperties;
        this.principalDetailsService = principalDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            String tokenHeader = request.getHeader("Authorization");
            String jwtToken = null;

            if(StringUtils.hasText(tokenHeader) && tokenHeader.startsWith("Bearer")) {
                jwtToken = tokenHeader.replace("Bearer ", "");
            }

            if(jwtToken != null && isValid(jwtToken)) {
                SecurityContextHolder.getContext().setAuthentication(getAuth(jwtToken));
            }

        }catch (Exception e) {
            throw new RuntimeException(e);
        }

        chain.doFilter(request, response);
    }

    private Authentication getAuth(String jwtToken) {
        PrincipalDetails user = (PrincipalDetails)principalDetailsService.loadUserByUsername(
                Jwts.parserBuilder()
                        .setSigningKey(jwtProperties.getSecretKey())
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
                    .setSigningKey(jwtProperties.getSecretKey())
                    .build()
                    .parseClaimsJws(jwtToken);

            if( jws == null ||
                    jws.getBody().getSubject() == null ||
                    jws.getBody().getExpiration().before(new Date())) {
                ret = false;
            }

            // TODO TOKEN 찾기 필요
//            String token = redisSubscriber.get(RedisTopicContact.getTopic(jws.getBody().getSubject())).toString();
//            if (token == null && !token.equals(jwtToken)) {
//                throw ErrorResponse.of(ErrorCode.UNAUTHORIZED);
//            }
        } catch (Exception e) {
            ret = false;
        }
        return ret;
    }
}

package com.example.springoauth.config.binder;

import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.sql.Blob;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
    private final Jwt jwt = new Jwt();
    private final OAuth2 oauth2 = new OAuth2();

    public Key getSecretKey() {
        byte[] keyBytes = this.getJwt().getSecret().getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static final class Jwt {
        private String secret;
        private Long expiration;
        private Long refreshTokenExpiry;

    }
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static final class OAuth2 {
        private List<String> authorizedRedirectUris = new ArrayList<>();

        public List<String> getAuthorizedRedirectUris() {
            return authorizedRedirectUris;
        }

        public OAuth2 authorizedRedirectUris(List<String> authorizedRedirectUris) {
            this.authorizedRedirectUris = authorizedRedirectUris;
            return this;
        }
    }
}

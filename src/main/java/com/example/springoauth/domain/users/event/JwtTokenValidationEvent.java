package com.example.springoauth.domain.users.event;

import lombok.Getter;

@Getter
public class JwtTokenValidationEvent {
    private String loginId;
    private String token;

    public JwtTokenValidationEvent(String loginId, String token) {
        this.loginId = loginId;
        this.token = token;
    }
}

package com.example.springoauth.domain.users.event;

import lombok.Getter;

@Getter
public class JwtTokenUpdateEvent {

    private String loginId;
    private String token;
    private String refreshToken;
    public JwtTokenUpdateEvent(String loginId, String token, String refreshToken) {
        this.loginId = loginId;
        this.token = token;
        this.refreshToken = refreshToken;
    }
}

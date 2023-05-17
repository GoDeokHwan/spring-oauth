package com.example.springoauth.domain.users.event;

import lombok.Getter;

@Getter
public class JwtTokenUpdateEvent {

    private String loginId;
    private String token;

    public JwtTokenUpdateEvent(String loginId, String token) {
        this.loginId = loginId;
        this.token = token;
    }
}

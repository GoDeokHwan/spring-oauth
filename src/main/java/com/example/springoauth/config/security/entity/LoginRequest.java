package com.example.springoauth.config.security.entity;

import lombok.Getter;

@Getter
public class LoginRequest {
    private String email;
    private String password;
}

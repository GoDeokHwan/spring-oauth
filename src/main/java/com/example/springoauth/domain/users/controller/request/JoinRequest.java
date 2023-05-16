package com.example.springoauth.domain.users.controller.request;

import lombok.Getter;

@Getter
public class JoinRequest {
    private String email;
    private String password;
}

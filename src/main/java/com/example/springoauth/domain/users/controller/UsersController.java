package com.example.springoauth.domain.users.controller;

import com.example.springoauth.domain.users.service.UsersService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class UsersController {

    private final UsersService usersService;
}

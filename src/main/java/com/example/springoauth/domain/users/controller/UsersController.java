package com.example.springoauth.domain.users.controller;

import com.example.springoauth.domain.users.controller.request.JoinRequest;
import com.example.springoauth.domain.users.service.UsersService;
import com.example.springoauth.entity.users.dto.UsersDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class UsersController {

    private final UsersService usersService;

    @PostMapping("/api/users/join")
    public ResponseEntity<UsersDTO> join(
            @RequestBody JoinRequest request
    ) {
        return ResponseEntity.ok(usersService.join(request));
    }
}

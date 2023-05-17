package com.example.springoauth.domain.users.event.listener.impl;

import com.example.springoauth.domain.users.event.JwtTokenValidationEvent;
import com.example.springoauth.domain.users.event.listener.JwtTokenValidationEventListener;
import com.example.springoauth.domain.users.service.UsersService;
import com.example.springoauth.entity.users.Users;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenValidationEventListenerImpl implements JwtTokenValidationEventListener {

    private final UsersService usersService;
    @Override
    public void handlerJwtTokenValidationEventListener(JwtTokenValidationEvent event) throws IllegalAccessException {
        if (StringUtils.hasText(event.getLoginId()) && StringUtils.hasText(event.getToken())) {
            Users users = usersService.getByEmail(event.getLoginId());
            if (!event.getToken().equals(users.getToken())) {
                throw new IllegalAccessException();
            }
        } else {
            throw new IllegalAccessException();
        }
    }
}

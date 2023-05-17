package com.example.springoauth.domain.users.event.listener.impl;

import com.example.springoauth.domain.users.event.JwtTokenUpdateEvent;
import com.example.springoauth.domain.users.event.listener.JwtTokenUpdateEventListener;
import com.example.springoauth.domain.users.service.UsersService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenUpdateEventListenerImpl implements JwtTokenUpdateEventListener {

    private final UsersService usersService;
    @Override
    public void handlerJwtTokenUpdateEventListener(JwtTokenUpdateEvent event) throws IllegalAccessException {
        if (StringUtils.hasText(event.getLoginId())) {
            usersService.updateToken(event.getLoginId(), event.getToken());
        } else {
            throw new IllegalAccessException();
        }
    }
}

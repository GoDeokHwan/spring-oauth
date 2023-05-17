package com.example.springoauth.domain.users.event.listener;

import com.example.springoauth.domain.users.event.JwtTokenUpdateEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;


public interface JwtTokenUpdateEventListener {
    @EventListener
    void handlerJwtTokenUpdateEventListener(JwtTokenUpdateEvent event) throws IllegalAccessException;
}

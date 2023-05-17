package com.example.springoauth.domain.users.event.listener;

import com.example.springoauth.domain.users.event.JwtTokenValidationEvent;
import org.springframework.context.event.EventListener;

public interface JwtTokenValidationEventListener {
    @EventListener
    void handlerJwtTokenValidationEventListener(JwtTokenValidationEvent event) throws IllegalAccessException;
}

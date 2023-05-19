package com.example.springoauth.config.security.oauth.info.impl;

import com.example.springoauth.config.security.oauth.info.OAuth2UserInfo;
import com.example.springoauth.entity.users.ProviderType;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(ProviderType providerType
            , Map<String, Object> attributes) {
        return switch (providerType) {
            case GOOGLE -> new GoogleOAuth2UserInfo(attributes);
            case NAVER -> new NaverOAuth2UserInfo(attributes);
            default -> throw new IllegalArgumentException();
        };
    }
}

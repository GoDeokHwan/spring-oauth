package com.example.springoauth.config.security.oauth.info.impl;

import com.example.springoauth.config.Contants;
import com.example.springoauth.config.security.oauth.info.OAuth2UserInfo;

import java.util.Map;

public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get(Contants.SUB);
    }

    @Override
    public String getName() {
        return (String) attributes.get(Contants.NAME);
    }

    @Override
    public String getEmail() {
        return (String) attributes.get(Contants.EMAIL);
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get(Contants.PICTURE);
    }
}

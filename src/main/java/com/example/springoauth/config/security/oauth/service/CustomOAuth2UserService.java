package com.example.springoauth.config.security.oauth.service;

import com.example.springoauth.config.security.entity.UserPrincipal;
import com.example.springoauth.config.security.oauth.info.OAuth2UserInfo;
import com.example.springoauth.config.security.oauth.info.impl.OAuth2UserInfoFactory;
import com.example.springoauth.domain.users.repository.UsersRepository;
import com.example.springoauth.entity.users.ProviderType;
import com.example.springoauth.entity.users.Users;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UsersRepository usersRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);

        try {
            return this.process(userRequest, user);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            throw new OAuth2AuthenticationException(ex.getMessage());
        }
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User user) {
        ProviderType providerType = ProviderType.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());
        // TODO 사용자 정보 조회
        Users users = usersRepository.findByEmail(userInfo.getEmail())
                .orElseGet(() -> createUser(userInfo, providerType));


        if (providerType != users.getProviderType()) {
            StringBuffer sb = new StringBuffer();
            sb.append("Looks like you're signed up with ");
            sb.append(providerType);
            sb.append(" account. Please use your ");
            sb.append(users.getProviderType());
            sb.append(" account to login.");
            throw new AuthenticationCredentialsNotFoundException(sb.toString());
        }

        updateUser(users, userInfo);

        return UserPrincipal.create(users, user.getAttributes());
    }

    private Users createUser(OAuth2UserInfo userInfo, ProviderType providerType) {
        return usersRepository.saveAndFlush(Users.ofCreate(userInfo.getEmail(), userInfo.getName(), userInfo.getImageUrl(), providerType));
    }

    private Users updateUser(Users user, OAuth2UserInfo userInfo) {
        if (userInfo.getName() != null && !user.getName().equals(userInfo.getName())) {
            user.changeName(userInfo.getName());
        }

        if (userInfo.getImageUrl() != null && !user.getFileImage().equals(userInfo.getImageUrl())) {
            user.changeImageUrl(userInfo.getImageUrl());
        }

        return user;
    }
}

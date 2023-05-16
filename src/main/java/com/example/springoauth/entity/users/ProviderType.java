package com.example.springoauth.entity.users;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ProviderType {
    ORIGIN("", "", "")
    , GOOGLE("static\\btn_google_signin_light_focus_web@2x.png", "image/png", "http://localhost:8080/oauth2/authorization/google?redirect_uri=http://localhost:8080/main")
    , NAVER("static\\btnG_완성형.png", "image/png", "")
    , KAKAO("static\\kakao_login_medium_narrow.png", "image/png", "")
    , INSTAR("", "", "")
    , FACEBOOK("", "", "")
    ;
    private final String path;
    private final String contentType;
    private final String oauthUrl;
}

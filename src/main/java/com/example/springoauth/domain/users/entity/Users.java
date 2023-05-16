package com.example.springoauth.domain.user.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Comment("ID")
    private Long id;

    @Column(length = 63)
    @Comment("로그인ID")
    private String loginId;

    @Column(length = 63)
    @Comment("이름")
    private String name;

    @Column(length = 511)
    @Comment("비밀번호")
    private String password;

    @Column(length = 127)
    @Comment("이메일")
    private String email;

    @Column
    @Comment("토큰")
    private String token;

    @Column
    @Comment("리플래시토큰")
    private String refreshToken;

    @Column
    @Comment("파일이미지")
    private String fileImage;

    @Column
    @Comment("생성일")
    @CreationTimestamp
    private LocalDateTime createDt;

    @Column
    @Comment("수정일")
    @UpdateTimestamp
    private LocalDateTime modifyDt;
}

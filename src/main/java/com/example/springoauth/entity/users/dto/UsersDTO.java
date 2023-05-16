package com.example.springoauth.entity.users.dto;

import com.example.springoauth.entity.users.ProviderType;
import com.example.springoauth.entity.users.RoleType;
import com.example.springoauth.entity.users.Users;
import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Getter;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Getter
public class UsersDTO {
    private Long id;
    private String email;
    private String name;
    private String fileImage;
    private ProviderType providerType;
    private RoleType roleType;
    private LocalDateTime createDt;
    private LocalDateTime modifyDt;

    public static UsersDTO ofUser(Users users) {
        UsersDTO instance = new UsersDTO();
        instance.id = users.getId();
        instance.email = users.getEmail();
        instance.name = users.getName();
        instance.fileImage = users.getFileImage();
        instance.providerType = users.getProviderType();
        instance.roleType = users.getRoleType();
        instance.createDt = users.getCreateDt();
        instance.modifyDt = users.getModifyDt();
        return instance;
    }
}

package com.example.springoauth.domain.common.controller;

import com.example.springoauth.entity.users.ProviderType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class FileController {

    @GetMapping("/api/attach-image")
    public ResponseEntity<Resource> attachImage(
            @RequestParam ProviderType type,
            HttpServletRequest request
            , HttpServletResponse response) throws IOException {

        ClassPathResource resource = switch (type) {
            case GOOGLE -> new ClassPathResource(type.getPath());
            case NAVER -> new ClassPathResource(type.getPath());
            case KAKAO -> new ClassPathResource(type.getPath());
            default -> throw new IllegalStateException();
        };
        HttpHeaders header = new HttpHeaders();
        header.add("Content-Type", type.getContentType());
        return new ResponseEntity<Resource>(resource, header, HttpStatus.OK);
    }
}

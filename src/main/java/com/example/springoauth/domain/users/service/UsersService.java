package com.example.springoauth.domain.users.service;

import com.example.springoauth.domain.users.controller.request.JoinRequest;
import com.example.springoauth.domain.users.repository.UsersRepository;
import com.example.springoauth.entity.users.Users;
import com.example.springoauth.entity.users.dto.UsersDTO;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UsersService {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    public UsersDTO join(JoinRequest request) {
        Users users = Users.ofProviderTypeByOrigin(request.getEmail(), passwordEncoder.encode(request.getPassword()));

        // TODO Mapper 는 향후 도입
        return UsersDTO.ofUser(usersRepository.save(users));
    }
}

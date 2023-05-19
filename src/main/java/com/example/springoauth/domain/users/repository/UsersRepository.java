package com.example.springoauth.domain.users.repository;

import com.example.springoauth.entity.users.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByEmail(String email);

    Optional<Users> findByEmailAndFileImage(String email, String fileImage);
}

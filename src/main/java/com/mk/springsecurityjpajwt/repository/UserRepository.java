package com.mk.springsecurityjpajwt.repository;

import com.mk.springsecurityjpajwt.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users, Long> {
    Users findByUsername(String username);
}

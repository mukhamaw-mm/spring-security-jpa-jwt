package com.mk.springsecurityjpajwt.repository;

import com.mk.springsecurityjpajwt.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);

}

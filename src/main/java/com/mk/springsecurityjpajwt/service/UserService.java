package com.mk.springsecurityjpajwt.service;

import com.mk.springsecurityjpajwt.entity.Role;

import com.mk.springsecurityjpajwt.entity.Users;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface UserService {
    List<Users> getUsers();
    Users getUser(String username);
    ResponseEntity saveUser(Users user);
    ResponseEntity saveRole(Role role);
    ResponseEntity addRoleToUser(String username, String roleName);


}

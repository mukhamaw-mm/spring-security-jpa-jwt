package com.mk.springsecurityjpajwt.service;

import com.mk.springsecurityjpajwt.entity.Role;
import com.mk.springsecurityjpajwt.entity.Users;
import com.mk.springsecurityjpajwt.repository.RoleRepository;
import com.mk.springsecurityjpajwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepository.findByUsername(username);
        if(user == null){
            log.error("User not found by username: {}", username);
            throw new UsernameNotFoundException("User not found in the database");
        }
        else {
            log.info("user is existed in the database: {}", username);
        }

        if(user.getRoles().isEmpty()){
            log.warn("role not found.");
            return new User(user.getUsername(), user.getPassword(), new ArrayList<>());
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(
                role -> authorities.add(new SimpleGrantedAuthority(role.getName()))
        );
        return new User(user.getUsername(), user.getPassword(), authorities);


    }
    @Override
    public List<Users> getUsers() {
        log.info("get all users");
        return userRepository.findAll();
    }

    @Override
    public Users getUser(String username) {
        log.info("get user by username: {}", username);
        return userRepository.findByUsername(username);
    }


    @Override
    public ResponseEntity saveUser(Users user) {
        log.info("saving user:{}", user);
        Map<String, String> errorMap = new HashMap<String, String>();
        if (user != null && user.getUsername() != null) {
            Users dbUser = userRepository.findByUsername(user.getUsername());

            if (dbUser != null) {
                log.error("User is already existed in the database: {}", user.getUsername());
                errorMap.put("error", "User is already existed in System");
                return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
            }
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user = userRepository.save(user);
            return new ResponseEntity(user, HttpStatus.CREATED);
        } else {
            errorMap.put("error", "Input is null");
            return new ResponseEntity(errorMap, HttpStatus.BAD_REQUEST);
        }

    }

    @Override
    public ResponseEntity saveRole(Role role) {
        log.info("saving role: {}", role);
        Map<String, String> errorMap = new HashMap<String, String>();
        if (role != null && role.getName() != null) {
            Role dbRole = roleRepository.findByName(role.getName());
            if (dbRole != null) {
                log.error("Role Name is already existed in the database: {}", role.getName());
                errorMap.put("error", "Role is already in System");
                return new ResponseEntity(errorMap, HttpStatus.BAD_REQUEST);
            }
            roleRepository.save(role);
            return new ResponseEntity<>(role, HttpStatus.CREATED);

        } else {
            errorMap.put("error", "Input is null");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }

    }

    @Override
    public ResponseEntity addRoleToUser(String username, String roleName) {
        log.info("add role to user, username: {}, roleName: {}",username, roleName);
        Map<String, String> errorMap = new HashMap<>();
        Users user = userRepository.findByUsername(username);
        if(user == null){
            log.error("Couldn't find user by username: {}", username);
            errorMap.put("error", "User Not Found");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }

        Role role = roleRepository.findByName(roleName);
        if(role == null){
            log.error("Couldn't find role by role name: {}", roleName);
            errorMap.put("error", "Role Name Not Found, Please add Role Name that you want.");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }
        Optional<Role> foundRole = user.getRoles().stream().filter(roleObj -> roleObj.getName().equals(roleName)).findFirst();
        if(foundRole.isPresent()){
            log.error("Input role name is already existed in user: {}, roleName: {}", username, roleName);
            errorMap.put("message", "Input role is already added in user");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }
        user.getRoles().add(role);// we don't need to call save method again as we declared @transactional, it will refresh and upload db, and do rollback if got error.
        return ResponseEntity.ok().build();

    }



}

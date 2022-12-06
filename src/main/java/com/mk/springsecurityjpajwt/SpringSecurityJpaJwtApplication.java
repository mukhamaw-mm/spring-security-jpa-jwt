package com.mk.springsecurityjpajwt;


import com.mk.springsecurityjpajwt.entity.Users;
import com.mk.springsecurityjpajwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJpaJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJpaJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


//    @Bean
//    CommandLineRunner run(UserService userService){
//        return args -> {
//            userService.saveRole(new Role(null, "SUPER_ADMIN"));
//            userService.saveRole(new Role(null, "ADMIN"));
//            userService.saveRole(new Role(null, "MANAGER"));
//            userService.saveRole(new Role(null, "NORMAL_USER"));

//            userService.saveUser(new Users(null, "mukham aw", "mukhamaw", "1234", new ArrayList<>()));
//            userService.saveUser(new Users(null, "aw lay", "awpay", "2345", new ArrayList<>()));
//            userService.saveUser(new Users(null, "aung aung", "aung", "5954", new ArrayList<>()));
//            userService.saveUser(new Users(null, "mg mg", "mg", "2324", new ArrayList<>()));
//
//            userService.addRoleToUser("mukhamaw", "NORMAL_USER");
//            userService.addRoleToUser("mk", "MANAGER");
//            userService.addRoleToUser("awpay", "MANAGER");
//            userService.addRoleToUser("mg", "SUPER_ADMIN");
//            userService.addRoleToUser("aung", "ADMIN");
//
//
//        };
//    }


}

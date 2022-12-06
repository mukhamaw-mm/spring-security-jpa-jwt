package com.mk.springsecurityjpajwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mk.springsecurityjpajwt.entity.Role;
import com.mk.springsecurityjpajwt.entity.Users;
import com.mk.springsecurityjpajwt.filter.CustomAuthenticationFilter;
import com.mk.springsecurityjpajwt.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    private final UserService userService;

    @GetMapping("/getAllUser")
    public ResponseEntity<List<Users>> getAllUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @GetMapping("/getUserByUsername")
    public ResponseEntity<Users> getUserByEmail(@RequestParam("username") String username){
        return ResponseEntity.ok().body(userService.getUser(username));
    }

    @PostMapping("/createUser")
    public ResponseEntity createUser(@RequestBody Users user){
        return userService.saveUser(user);
    }

    @PostMapping("/role/createRole")
    public ResponseEntity createRole(@RequestBody Role role){
        return userService.saveRole(role);
    }

    @PostMapping("/role/addRoleToUser")
    public ResponseEntity addRoleToUser(@RequestBody AddRoleToUserRequest addRoleToUserRequest){
        return userService.addRoleToUser(addRoleToUserRequest.getUsername(), addRoleToUserRequest.getRoleName());
    }

    @GetMapping("/token/refresh")
    public void tokenRefresh(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try{
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            String bearer = "Bearer "; // include space behind Bearer as key will follow after space
            if (authorizationHeader != null && authorizationHeader.startsWith(bearer)) {
                String refreshToken = authorizationHeader.substring(bearer.length());
                Algorithm algorithm = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
                JWTVerifier jwtVerifier = JWT.require(algorithm).build(); // create JWT verify with algorithm to verify user input token.
                DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken); // decode token
                String [] roles = decodedJWT.getClaim("roles").asArray(String.class);

                if(roles != null && roles.length != 0) {
                    throw new RuntimeException("Token is not valid.");
                }

                String username = decodedJWT.getSubject(); // subject will be email as we gave that in CustomAuthenticationFilter class.

                Users user = userService.getUser(username);
                Algorithm algorithms = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
                String accessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 3 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithms);
                response.setContentType(APPLICATION_JSON_VALUE);

                TokenResponse tokenObject = new TokenResponse();
                tokenObject.setAccessToken(accessToken);
                tokenObject.setRefreshToken(refreshToken);

                new ObjectMapper().writeValue(response.getOutputStream(), tokenObject);


            }else {
                throw new RuntimeException("Token format is wrong");
            }
        }catch (Exception e){
            response.setHeader("error ", e.getMessage());
            response.setStatus(FORBIDDEN.value());
            Map<String, String> errorJson = new HashMap<>();
            errorJson.put("error: ", e.getMessage());
            errorJson.put("code: ", String.valueOf(FORBIDDEN.value()));
            errorJson.put("message: ", "Your input refresh token is something wrong");
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), errorJson);
        }
    }

    @Data
    class AddRoleToUserRequest {
        private String username;
        private String roleName;
    }

    @Data
    class TokenResponse{
        private String accessToken;
        private String refreshToken;
    }

}

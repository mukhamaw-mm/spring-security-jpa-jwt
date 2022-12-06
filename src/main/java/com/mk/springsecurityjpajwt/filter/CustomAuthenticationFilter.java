package com.mk.springsecurityjpajwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("username: {}, password: {}", username, password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        // to do authenticate with user input username and password with our database username and password,
        // Firstly, it will go to UserServiceImpl class loadUserByUsername method and find as per username (email) and if user existed, it will do authenticate
        return  authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        Algorithm algorithms = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 3* 60* 1000))
                .withIssuer(request.getRequestURI().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithms);

        // refresh token will use when above access token was expired.
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 90 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithms);
        response.setContentType(APPLICATION_JSON_VALUE);

        // we can return tokens back in body with json format by using java object
        TokenResponse tokenObject = new TokenResponse();
        tokenObject.setAccessToken(accessToken);
        tokenObject.setRefreshToken(refreshToken);
        // return access token and refresh token after login was successful by using output stream.
        // Actually, response object already return, but we need to define what data we will return (eg. token) and what type (eg. json) we will return back.
        new ObjectMapper().writeValue(response.getOutputStream(), tokenObject);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        /**
         * This method will process when the authentication was unsuccessful,
         * This method will process after loadUserByUsername method of UserServiceImpl class.
         * eg. wrong username or wrong password.
         */

        response.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part after calling api.
        log.warn("warning: {}", failed.getMessage());


        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", failed.getMessage());
        new ObjectMapper().writeValue(response.getOutputStream(), errorMap);
    }

    @Data
    class TokenResponse{
        private String accessToken;
        private String refreshToken;
}
}

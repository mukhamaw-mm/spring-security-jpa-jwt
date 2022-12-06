package com.mk.springsecurityjpajwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.persister.collection.OneToManyPersister;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        try{
            if (httpServletRequest.getServletPath().equals("/login") || httpServletRequest.getServletPath().equals("/user/token/refresh")){
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }else {
                String authorizationHeader = httpServletRequest.getHeader(AUTHORIZATION);
                String bearer = "Bearer "; // include space behind Bearer as key will follow after space

                if (authorizationHeader != null && authorizationHeader.startsWith(bearer)) {
                    String token = authorizationHeader.substring(bearer.length());
                    Algorithm algorithm = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build(); // create JWT verify with algorithm to verify user input token.
                    DecodedJWT decodedJWT = jwtVerifier.verify(token); // decode token
                    String username = decodedJWT.getSubject(); // subject will be email as we gave that in CustomAuthenticationFilter class.
                    // retrieve roles from claim by using key 'roles' as we gave that in CustomAuthenticationFilter class.
                    String [] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    if(roles != null && roles.length != 0) {
                        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                        stream(roles).forEach(role -> {
                            authorities.add(new SimpleGrantedAuthority(role)); // convert string array roles to SimpleGrantedAuthority list (authorities) because spring framework only know this object for permission authorities cases.
                        });
                        UsernamePasswordAuthenticationToken usrNamePwdAuthenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(usrNamePwdAuthenticationToken);
                        filterChain.doFilter(httpServletRequest, httpServletResponse);


                    }else {
                        filterChain.doFilter(httpServletRequest, httpServletResponse);
                    }
                }
            }

        }catch (Exception e){
            log.error("error: {}", e.getMessage());
            httpServletResponse.setHeader("error ", e.getMessage());
            httpServletResponse.setStatus(FORBIDDEN.value());

            Map<String, String> errorJson = new HashMap<>();
            errorJson.put("error: ", e.getMessage());
            errorJson.put("code: ", String.valueOf(FORBIDDEN.value()));
            errorJson.put("message: ", "Your input token is something wrong");
            httpServletResponse.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part.
            // return json type data by writing output stream to httpServletResponse
            new ObjectMapper().writeValue(httpServletResponse.getOutputStream(), errorJson);
        }
    }
}

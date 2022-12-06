package com.mk.springsecurityjpajwt.security;

import com.mk.springsecurityjpajwt.filter.CustomAuthenticationFilter;
import com.mk.springsecurityjpajwt.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bcryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bcryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/user/login");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilter(customAuthenticationFilter);
        http.authorizeRequests().antMatchers("/user/login/**", "/user/token/refresh").permitAll();
        http.authorizeRequests().antMatchers(GET, "/user/**").hasAnyAuthority("NORMAL_USER", "MANAGER", "ADMIN" , "SUPER_ADMIN");
        http.authorizeRequests().antMatchers(POST, "/user/createUser").hasAnyAuthority("MANAGER", "ADMIN", "SUPER_ADMIN");
        http.authorizeRequests().antMatchers(POST, "/user/role/**").hasAnyAuthority("ADMIN", "SUPER_ADMIN");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        // allow for all api endpoint url for any role and any user without defining access api permission by which roles.
        // we comment out below line because we want to do authorization for each api endpoints (authorization - decide which user and roles can access which api)
//        http.authorizeRequests().anyRequest().permitAll();

    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}

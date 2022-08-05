package com.pineapple.auth.service.infra.config;

import com.nimbusds.jwt.JWT;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    private final AuthenticationSuccessHandler successHandler;

    private final Filter preAuthenticationFilter;

    private final AuthenticationManager authenticationManager;


    public SecurityConfig(
            @Qualifier("OAuth2SuccessHandler") AuthenticationSuccessHandler successHandler,
            @Qualifier("preAuthenticationFilter") Filter preAuthenticationFilter,
            @Qualifier("jwtAuthenticationManager") AuthenticationManager jwtAuthenticationManager) {
        this.successHandler = successHandler;
        this.preAuthenticationFilter = preAuthenticationFilter;
        this.authenticationManager = jwtAuthenticationManager;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest().fullyAuthenticated()
                .and()
                    .oauth2Login()
                        .successHandler(successHandler)
                .and()
                    .csrf()
                        .disable()
                .addFilterBefore(preAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .oauth2ResourceServer()
                    .jwt()
                        .authenticationManager(authenticationManager);
    }

    @Bean
    public List<Consumer<JWT>> jwtVerifiers(
            @Qualifier("signatureVerifier") Consumer<JWT> signatureVerifier,
            @Qualifier("notBeforeTimeClaimsVerifier") Consumer<JWT> notBeforeTimeVerifier,
            @Qualifier("validityClaimsVerifier") Consumer<JWT> validityVerifier) {
        return new ArrayList<>() {{
            add(signatureVerifier);
            add(notBeforeTimeVerifier);
            add(validityVerifier);
        }};
    }
}

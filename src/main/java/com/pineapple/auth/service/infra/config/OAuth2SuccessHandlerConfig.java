package com.pineapple.auth.service.infra.config;

import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

@Configuration
public class OAuth2SuccessHandlerConfig {

    @Bean
    public List<BiConsumer<AuthenticationEvent, AuthenticationContext>> authenticationListeners (
            @Qualifier("roleVerifierListener") BiConsumer<AuthenticationEvent, AuthenticationContext> roleVerifierListener,
            @Qualifier("authenticationAdjusterListener") BiConsumer<AuthenticationEvent, AuthenticationContext> adjusterListener,
            @Qualifier("jsonUserWriterListener") BiConsumer<AuthenticationEvent, AuthenticationContext> jsonUserWriterListener,
            @Qualifier("authorizationListener") BiConsumer<AuthenticationEvent, AuthenticationContext> authorizationListener,
            @Qualifier("redirectListener") BiConsumer<AuthenticationEvent, AuthenticationContext> redirectListener) {
        var listeners = new ArrayList<BiConsumer<AuthenticationEvent, AuthenticationContext>>();
        listeners.add(roleVerifierListener);
        listeners.add(adjusterListener);
        listeners.add(jsonUserWriterListener);
        listeners.add(authorizationListener);
        listeners.add(redirectListener);
        return listeners;
    }
}

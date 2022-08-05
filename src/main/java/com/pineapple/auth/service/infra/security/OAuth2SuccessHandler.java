package com.pineapple.auth.service.infra.security;

import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final List<BiConsumer<AuthenticationEvent, AuthenticationContext>> listeners;

    public OAuth2SuccessHandler(
            @Qualifier("authenticationListeners") List<BiConsumer<AuthenticationEvent, AuthenticationContext>> authenticationListeners) {
        this.listeners = new ArrayList<>(authenticationListeners.size());
        this.listeners.addAll(authenticationListeners);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        var event = new AuthenticationEvent(authentication, request, response);
        var context = new AuthenticationContext();
        for (var listener : listeners) {
            listener.accept(event, context);
        }
    }
}

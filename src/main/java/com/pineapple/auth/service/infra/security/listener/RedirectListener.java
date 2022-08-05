package com.pineapple.auth.service.infra.security.listener;

import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.function.BiConsumer;

@Component
public class RedirectListener implements BiConsumer<AuthenticationEvent, AuthenticationContext> {

    @Override
    public void accept(AuthenticationEvent event, AuthenticationContext authenticationContext) {
        var response = event.getResponse();

        var redirectUri = event.getRequest().getRequestURI(); // Redirects to source url
        var uri = String.format("%s?token=%s&user=%s",
                redirectUri,
                authenticationContext.getToken(),
                authenticationContext.getJsonUser());

        response.setStatus(HttpStatus.MOVED_PERMANENTLY.value());
        response.setHeader(HttpHeaders.LOCATION, uri);
    }
}

package com.pineapple.auth.service.infra.security.listener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import com.pineapple.commons.domain.user.Authority;
import com.pineapple.commons.domain.user.PineappleUser;
import com.pineapple.commons.domain.user.Role;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.function.BiConsumer;
import java.util.stream.Collectors;

@Component
@AllArgsConstructor
public class JsonUserWriterListener implements BiConsumer<AuthenticationEvent, AuthenticationContext> {

    private final ObjectMapper mapper;

    @Override
    public void accept(AuthenticationEvent event, AuthenticationContext context) {
        var auth = (OAuth2AuthenticationToken) event.getAuthentication();
        var user = new PineappleUser(
                auth.getName(),
                auth.getPrincipal().getAttribute("email"),
                context.getRoles()
                        .stream()
                        .map(r -> new Authority(r))
                        .collect(Collectors.toList()));
        try {
            context.setJsonUser(mapper.writeValueAsString(user));
            context.setUser(user);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

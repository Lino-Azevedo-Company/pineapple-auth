package com.pineapple.auth.service.infra.security.listener;

import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import com.pineapple.commons.domain.user.Role;
import lombok.AllArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;

import java.util.LinkedList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

@Component
@AllArgsConstructor
public class AuthenticationAdjusterListener implements BiConsumer<AuthenticationEvent, AuthenticationContext> {

    public static final String USERNAME_ATTRIBUTE = "spring.security.oauth2.client.provider.sdm.userNameAttribute";
    private static final String ROLE_PREFIX = "ROLE_";
    private final Environment environment;

    @Override
    public void accept(AuthenticationEvent event, AuthenticationContext context) {
        var auth = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        var user = auth.getPrincipal();
        var roles = getRoles(event);

        var authorities = roles
                .stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role.name()))
                .collect(Collectors.toList());

        var newUser = new DefaultOAuth2User(
                authorities,
                user.getAttributes(),
                environment.getProperty(USERNAME_ATTRIBUTE));

        var newAuth = new OAuth2AuthenticationToken(newUser, authorities, auth.getAuthorizedClientRegistrationId());
        var securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(newAuth);

        SecurityContextHolder.clearContext();
        SecurityContextHolder.setContext(securityContext);
    }

    private List<Role> getRoles(AuthenticationEvent event) {
        var roles = new LinkedList<Role>();
        for (String roleName : event.getRoles()) {
            var role = Role.getByName(roleName);
            if (role != null) {
                roles.add(role);
            }
        }
        return roles;
    }
}

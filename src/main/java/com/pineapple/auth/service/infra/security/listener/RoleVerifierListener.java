package com.pineapple.auth.service.infra.security.listener;

import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import com.pineapple.commons.domain.user.Role;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.stereotype.Component;

import java.util.LinkedList;
import java.util.List;
import java.util.function.BiConsumer;

@Component
public class RoleVerifierListener implements BiConsumer<AuthenticationEvent, AuthenticationContext> {

    @Override
    public void accept(AuthenticationEvent authenticationEvent, AuthenticationContext authenticationContext) {
        if (!(getRoles(authenticationEvent, authenticationContext).size() > 0)) {
            throw new InsufficientAuthenticationException("user without permission");
        }
    }

    private List<Role> getRoles(AuthenticationEvent event, AuthenticationContext context) {
        var roles = new LinkedList<Role>();
        for (var roleName : event.getRoles()) {
            var role = Role.getByName(roleName);
            if (role != null) {
                roles.add(role);
            }
        }
        context.setRoles(roles);
        return roles;
    }
}

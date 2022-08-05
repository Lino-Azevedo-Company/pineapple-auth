package com.pineapple.auth.service.infra.security.event;

import lombok.Getter;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public class AuthenticationEvent extends AbstractAuthenticationEvent {

    private final HttpServletRequest request;
    private final HttpServletResponse response;

    public AuthenticationEvent(Authentication authentication,
                               HttpServletRequest request,
                               HttpServletResponse response) {
        super(authentication);
        this.request = request;
        this.response = response;
    }

    public List<String> getRoles() {
        var auth = (OAuth2AuthenticationToken) getAuthentication();
        var principal = auth.getPrincipal();
        return principal.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }
}

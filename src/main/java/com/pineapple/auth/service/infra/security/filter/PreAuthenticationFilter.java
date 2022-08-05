package com.pineapple.auth.service.infra.security.filter;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class PreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final int BEARER = 7; // 'BEARER ' character size

    public PreAuthenticationFilter(
            @Qualifier("jwtAuthenticationManager") AuthenticationManager authenticationManager) {
        setAuthenticationManager(authenticationManager);
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        var auth = request.getHeader(HttpHeaders.AUTHORIZATION);
        return (auth != null && auth.length() > BEARER) ?
            auth.substring(BEARER) :
                null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return null;
    }
}

package com.pineapple.auth.service.infra.security.listener;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pineapple.auth.service.infra.security.event.AuthenticationContext;
import com.pineapple.auth.service.infra.security.event.AuthenticationEvent;
import com.pineapple.commons.exception.InternalServerErrorException;
import com.pineapple.commons.exception.JwtTokenException;
import com.pineapple.commons.infra.config.ConfigurationRetriever;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

@Component
public class AuthorizationListener implements BiConsumer<AuthenticationEvent, AuthenticationContext> {

    private static final long TEN_HOURS_IN_SECONDS = 3600000L * 10;

    private final JWSSigner signer;
    private final String issuer;

    public AuthorizationListener(ConfigurationRetriever retriever) {
        try {
            this.signer = new MACSigner(retriever.getEnv("JWT_SECRET"));
        } catch (KeyLengthException e) {
            throw new InternalServerErrorException(e);
        }
        this.issuer = retriever.getEnv("JWT_ISSUER");
    }

    @Override
    public void accept(AuthenticationEvent event, AuthenticationContext context) {
        var claims = buildClaims(event, context);
        signToken(context, claims);
    }

    private JWTClaimsSet buildClaims(AuthenticationEvent event, AuthenticationContext context) {
        var user = context.getUser();
        var auth = SecurityContextHolder.getContext().getAuthentication();
        var oauthUser = (DefaultOAuth2User) auth.getPrincipal();

        var authorities = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        var attributes = oauthUser.getAttributes();

        var now = System.currentTimeMillis();
        return new JWTClaimsSet.Builder()
                .subject(auth.getName())
                .issuer(issuer)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + TEN_HOURS_IN_SECONDS))
                .notBeforeTime(new Date(now))
                .claim("name", String.valueOf(attributes.get("name")))
                .claim("email", String.valueOf(attributes.get("email")))
                .claim("role", user.getRole())
                .claim("authorities", authorities)
                .build();
    }

    private void signToken(AuthenticationContext context, JWTClaimsSet claims) {
        var signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new JwtTokenException("Could not sign token");
        }

        var token = signedJWT.serialize();
        context.setToken(token);
    }
}

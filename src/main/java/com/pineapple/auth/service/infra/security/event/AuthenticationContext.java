package com.pineapple.auth.service.infra.security.event;

import com.pineapple.commons.domain.user.PineappleUser;
import com.pineapple.commons.domain.user.Role;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class AuthenticationContext {

    PineappleUser user;
    private String token;
    private String jsonUser;

    private List<Role> roles;
}

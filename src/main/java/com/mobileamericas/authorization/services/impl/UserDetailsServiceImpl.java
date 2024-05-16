package com.mobileamericas.authorization.services.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.mobileamericas.authorization.infrastructure.config.GoogleOAuthParamsConfig;
import com.mobileamericas.authorization.infrastructure.persistence.entities.UserEntity;
import com.mobileamericas.authorization.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@AllArgsConstructor
@Service
public class UserDetailsServiceImpl implements AuthenticationUserDetailsService {

    private UserService userService;
    private GoogleOAuthParamsConfig googleOAuthParamsConfig;
    @Override
    public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {
        GoogleIdToken idToken = (GoogleIdToken)authentication.getCredentials();
        String clientId = idToken.getPayload().getAudience().toString();
        String app = googleOAuthParamsConfig.getApp(clientId);

        return loadUserByUsernameAndApp(authentication.getPrincipal().toString(), app);
    }

    @Transactional
    public UserDetails loadUserByUsernameAndApp(String username, String app) throws UsernameNotFoundException {
        return userService.findByEmail(username)
                .filter(user -> user.getRoles().stream().anyMatch(rol -> rol.getApp().getName().equals(app)))
                .map(user -> User.builder()
                        .username(user.getEmail())
                        .password(app)
                        .authorities(getAuthorities(user, app))
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(String.format("The customer %s was not found", username)));
    }

    private Set<GrantedAuthority> getAuthorities(UserEntity user, String app) {
        return user.getRoles().stream()
                .filter(rol -> rol.getApp().getName().equals(app))
                .flatMap(rol -> Stream.concat(
                        Stream.of("ROLE_" + rol.getName()),
                        rol.getPermissions().stream().map(permission -> permission.getName())
                ))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

}

package com.mobileamericas.authorization.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Set;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetail extends User {
    private Long id;
    private String fullName;
    private String app;
    private Set<Role> roles;
    private String avatar;

    public CustomUserDetail(String username, String password, Collection<? extends GrantedAuthority> authorities,
                            Long id, String fullName, String app, Set<Role> roles, String avatar) {
        super(username, password, authorities);
        this.id = id;
        this.fullName = fullName;
        this.app = app;
        this.roles = roles;
        this.avatar = avatar;
    }

    public static CustomUserDetailBuilder customBuilder() {
        return new CustomUserDetailBuilder();
    }

    public static class CustomUserDetailBuilder {
        private String username;
        private String password;
        private Collection<? extends GrantedAuthority> authorities;
        private Long id;
        private String fullName;
        private String app;
        private Set<Role> roles;
        private String avatar;

        public CustomUserDetailBuilder username(String username) {
            this.username = username;
            return this;
        }

        public CustomUserDetailBuilder password(String password) {
            this.password = password;
            return this;
        }

        public CustomUserDetailBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
            this.authorities = authorities;
            return this;
        }

        public CustomUserDetailBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public CustomUserDetailBuilder fullName(String fullName) {
            this.fullName = fullName;
            return this;
        }

        public CustomUserDetailBuilder app(String app) {
            this.app = app;
            return this;
        }

        public CustomUserDetailBuilder roles(Set<Role> roles) {
            this.roles = roles;
            return this;
        }

        public CustomUserDetailBuilder avatar(String avatar) {
            this.avatar = avatar;
            return this;
        }

        public CustomUserDetail build() {
            return new CustomUserDetail(username, password, authorities, id, fullName, app, roles, avatar);
        }
    }
}

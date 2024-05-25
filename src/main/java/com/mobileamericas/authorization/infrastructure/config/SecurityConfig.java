package com.mobileamericas.authorization.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mobileamericas.authorization.infrastructure.security.CustomAuthenticationProvider;
import com.mobileamericas.authorization.infrastructure.web.JwtAuthFilter;
import com.mobileamericas.authorization.utils.JwtUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${authentication.cookie.access.name}")
    private String COOKIE_ACCESS_NAME;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, JwtUtil jwtUtil, ObjectMapper objectMapper, AuthenticationManager authenticationManager) throws Exception {
        return httpSecurity
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    http.requestMatchers(HttpMethod.GET, "/v1/authorization/health-check").permitAll();
                    http.requestMatchers(HttpMethod.GET, "/v1/authorization/env").permitAll();
                    http.requestMatchers(HttpMethod.POST, "/v1/authorization/google").permitAll();
                    http.requestMatchers(HttpMethod.GET, "/v1/authorization/role").authenticated();
                    http.requestMatchers(HttpMethod.POST, "/v1/authorization").hasAnyRole("admin");
                    http.requestMatchers(HttpMethod.OPTIONS,"/**").permitAll();
                    http.requestMatchers("/error").permitAll();
                    http.requestMatchers("/logout").permitAll();
                    http.requestMatchers("/login").permitAll();
                    http.anyRequest().permitAll();
                })
                .addFilterBefore(new JwtAuthFilter(COOKIE_ACCESS_NAME, objectMapper, authenticationManager, jwtUtil), BasicAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(AuthenticationUserDetailsService userDetailsService) {
        CustomAuthenticationProvider customAuthenticationProvider = new CustomAuthenticationProvider(userDetailsService);
        return customAuthenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return StringUtils.equalsIgnoreCase(rawPassword.toString(), encodedPassword);
            }
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("http://localhost:3000");
        configuration.addAllowedOriginPattern("http://*.mobile-americas.com");
        configuration.addAllowedOriginPattern("https://*.mobile-americas.com");
        configuration.addAllowedHeader("*");
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization", "X-Requested-With", "Origin", "Accept"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

package com.mobileamericas.authorization.infrastructure.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "google.oauth")
@Getter
@Setter
public class GoogleOAuthParamsConfig {

    @AllArgsConstructor
    enum GoogleOAuthParams {
        APP("app"), ID("id");
        String name;
    }

    private List<Map<String, String>> clientList;

    public Set<String> getClientIdList() {
        return clientList.stream()
                .map(entry -> entry.get(GoogleOAuthParams.ID.name))
                .collect(Collectors.toSet());
    }

    public String getApp(String id) {
        return clientList.stream()
                .filter(entry -> entry.get(GoogleOAuthParams.ID.name).equals(id))
                .map(entry -> entry.get(GoogleOAuthParams.APP.name))
                .findFirst()
                .orElse(null);
    }
}

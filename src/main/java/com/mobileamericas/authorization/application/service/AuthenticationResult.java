package com.mobileamericas.authorization.application.service;

import java.time.Duration;
import java.time.Instant;

public record AuthenticationResult(
        String accessToken,
        String refreshToken,
        Duration accessTtl,
        Instant refreshExpiresAt) {}

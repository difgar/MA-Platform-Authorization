package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.AccessGrant;

import java.time.Duration;

public interface TokenIssuer {

    String issueAccessToken(AccessGrant grant);

    Duration accessTokenTtl();
}

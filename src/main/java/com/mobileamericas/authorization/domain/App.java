package com.mobileamericas.authorization.domain;

import java.util.UUID;

public record App(UUID id, String name, String googleClientId, String url, boolean active) {}

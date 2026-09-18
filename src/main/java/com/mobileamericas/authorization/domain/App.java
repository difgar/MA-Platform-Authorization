package com.mobileamericas.authorization.domain;

import java.util.UUID;

public record App(UUID id, String name, String url, boolean active) {}

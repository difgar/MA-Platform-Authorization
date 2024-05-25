package com.mobileamericas.authorization.services;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

public interface GoogleOAuthService {

    void validateToken(String token) throws GeneralSecurityException, IOException;

    List<Map<String,String>> getMapClientIds();
}

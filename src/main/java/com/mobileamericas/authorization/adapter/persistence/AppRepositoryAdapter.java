package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.domain.App;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
@Transactional(readOnly = true)
class AppRepositoryAdapter implements AppRepository {

    private final JpaAppRepository jpa;

    AppRepositoryAdapter(JpaAppRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    public Optional<App> findByName(String name) {
        return jpa.findByName(name).map(DomainMapper::toDomain);
    }

    @Override
    public Set<String> resourceCatalogue(UUID appId) {
        return Set.copyOf(jpa.findResourcesByAppId(appId.toString()));
    }
}

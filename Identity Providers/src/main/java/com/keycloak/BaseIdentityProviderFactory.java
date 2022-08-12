package com.keycloak;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class BaseIdentityProviderFactory extends AbstractIdentityProviderFactory<BaseIdentityProvider> implements SocialIdentityProviderFactory<BaseIdentityProvider> {

    public static final String PROVIDER_ID = "base";

    @Override
    public String getName() {
        return PROVIDER_ID;
    }

    @Override
    public BaseIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new BaseIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }
}
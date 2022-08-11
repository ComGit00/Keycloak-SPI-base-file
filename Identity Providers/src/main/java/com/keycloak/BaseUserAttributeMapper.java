package com.keycloak;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

/**
 * User attribute mapper.
 */
public class BaseUserAttributeMapper extends AbstractJsonUserAttributeMapper {

	private static final String[] cp = new String[] { BaseIdentityProviderFactory.PROVIDER_ID };

	@Override
	public String[] getCompatibleProviders() {
		return cp;
	}

	@Override
	public String getId() {
		return "base-user-attribute-mapper";
	}

}
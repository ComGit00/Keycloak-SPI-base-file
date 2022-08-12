package com.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.Iterator;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

public class BaseIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

	public static final String HOST = "https://kauth.kakao.com"; 			// OAUTH host 
	public static final String AUTH_URL = ""; 		// 인증 
	public static final String TOKEN_URL = "";  	// 토큰
	public static final String PROFILE_URL = "";	// resource access url 
	public static final String DEFAULT_SCOPE = "";	//	scope 값이 필요시

	//	keycloak 연결시 기본 정보 세팅
	public BaseIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
		super(session, config);
		
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
		config.setUserInfoUrl(PROFILE_URL);
	}

	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

    //  네이버 Profile Endpoint 주소 반환
	@Override
	protected String getProfileEndpointForValidation(EventBuilder event) {
		return PROFILE_URL;
	}

    //  네이버 Profile 내용 반환
	//	필수값(이메일, 성 , 이름-) 입력시 따로 페이지를 거치지 않고 바로 로그인 됨
	@Override
	protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
		// getJsonProperty 는 Oidc 관련 파싱만 가능하므로 JsonNode 의 get 메소드를 이용해서 가져온다.
		// BrokeredIdentityContext user = new BrokeredIdentityContext(profile.get("id").asText());
		BrokeredIdentityContext user = new BrokeredIdentityContext(profile.get("response").get("id").asText());
		//	사용자 정보에서 이메일 가져오기
		String email = profile.get("response").get("email").asText();

		user.setIdpConfig(getConfig());
		user.setUsername(email);
		user.setEmail(email);
		user.setIdp(this);

		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

		return user;
	}

    //  실제로 네이버에 인증 요청을 하고 토큰을 받아오는 역할, 토큰을 이용해 Profile 을 가져오는 역할을 수행하는 메소드이다.
	@Override
	protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
		try {
			//	토큰값 가져와서 사용자 정보 가져오기
			// JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
			JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).param("access_token", accessToken).asJson();

			BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);

			return user;
		} catch (Exception e) {
			throw new IdentityBrokerException("Could not obtain user profile from naver.", e);
		}
	}

	//	scope 값이 필요할시 호출 함수
	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}
}
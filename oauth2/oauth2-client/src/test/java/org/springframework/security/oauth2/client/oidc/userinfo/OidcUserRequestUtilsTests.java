/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.client.oidc.userinfo;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class OidcUserRequestUtilsTests {

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration();

	OidcIdToken idToken = TestOidcIdTokens.idToken().build();

	OAuth2AccessToken accessTokenWithProfileScope = TestOAuth2AccessTokens.scopes(OidcScopes.PROFILE, "read:user");

	OAuth2AccessToken accessTokenWithoutProfileScope = TestOAuth2AccessTokens.scopes("read:user");

	@Test
	public void shouldRetrieveUserInfoWhenEndpointDefinedAndScopesOverlapThenTrue() {
		assertThat(OidcUserRequestUtils.shouldRetrieveUserInfo(userRequestWithProfileScope())).isTrue();
	}

	@Test
	public void shouldRetrieveUserInfoWhenNoUserInfoUriThenFalse() {
		this.registration.userInfoUri(null);
		assertThat(OidcUserRequestUtils.shouldRetrieveUserInfo(userRequestWithProfileScope())).isFalse();
	}

	@Test
	public void shouldRetrieveUserInfoWhenDifferentScopesThenFalse() {
		assertThat(OidcUserRequestUtils.shouldRetrieveUserInfo(userRequestWithoutProfileScope())).isFalse();
	}

	@Test
	public void shouldRetrieveUserInfoWhenNotAuthorizationCodeThenFalse() {
		this.registration.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(OidcUserRequestUtils.shouldRetrieveUserInfo(userRequestWithProfileScope())).isFalse();
	}

	private OidcUserRequest userRequestWithProfileScope() {
		return new OidcUserRequest(this.registration.build(), this.accessTokenWithProfileScope, this.idToken);
	}

	private OidcUserRequest userRequestWithoutProfileScope() {
		return new OidcUserRequest(this.registration.build(), this.accessTokenWithoutProfileScope, this.idToken);
	}

}

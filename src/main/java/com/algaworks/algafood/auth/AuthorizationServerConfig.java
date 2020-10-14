package com.algaworks.algafood.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig  extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	//@Autowired
	//private RedisConnectionFactory redisConnectionFactory;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write","read")
				.accessTokenValiditySeconds(60 * 60 * 6) // 6 horas
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias
			.and()
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write","read")
			.and()
				.withClient("foodanalytics")
				//.secret(passwordEncoder.encode("food123"))
				.secret(passwordEncoder.encode("")) // sem autenticar cliente, somente com pkce
				.authorizedGrantTypes("authorization_code")
				.scopes("write","read")
				.redirectUris("http://127.0.0.1:5500/algafood-js/") // client js
				//.redirectUris("http://aplicacao-cliente/")
			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write","read")
				.redirectUris("http://aplicacao-cliente/")
			.and()
				.withClient("checktoken")
				.secret(passwordEncoder.encode("check123")); 
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security
			.checkTokenAccess("isAuthenticated()")
			.allowFormAuthenticationForClients();
//		security.checkTokenAccess("permiteAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			//.tokenStore(redisTokenStore())
			.accessTokenConverter(jwtAccessTokenConverter())
			.tokenGranter(tokenGranter(endpoints));
	}
	
	//private TokenStore redisTokenStore() {
	//	return new RedisTokenStore(redisConnectionFactory);
	//}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();
		//jwtAccessTokenConverter.setSigningKey("da87d98s7d89sa78das78d9sa787da8d7sa8da78s9jj");
		
		var jksResource = new ClassPathResource("keystores/algafood.jks");
		var keyStorePass = "123456";
		var keyPairAlias = "algafood";
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		return jwtAccessTokenConverter;
	}
	

	// Parte da configuração do Authorization Server, para adicionar o TokenGranter customizado
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}

}

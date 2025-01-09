package io.pay.bly.authserver.config.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            JwtDecoder jwtDecoder,
            @Qualifier("registeredClientRepository") RegisteredClientRepository registeredClientRepository,
            UserDetailsService userDetailsService,
            AuthorizationServerSettings authorizationServerSettings,
            PasswordEncoder passwordEncoder) throws Exception {

        // 1) Create the Authorization Server configurer
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        // 2) Apply it with an inline Customizer
        http.with(authorizationServerConfigurer, authServer -> {
            // For example, enable OpenID Connect
            authServer.oidc(Customizer.withDefaults());

            // Optionally set a custom authorizationService, tokenGenerator, etc.
            authServer
                    .registeredClientRepository(registeredClientRepository)
                    .authorizationService(authorizationService())
                    .authorizationServerSettings(authorizationServerSettings)
                    .authorizationEndpoint((oAuth2AuthorizationEndpointConfigurer ->
                                    oAuth2AuthorizationEndpointConfigurer
                                            .authenticationProvider(authenticationProvider)))
                    .clientAuthentication(clientAuth -> clientAuth.authenticationProvider(oAuth2ClientCredentialsAuthenticationProvider()))
                    .tokenGenerator(tokenGenerator());
        });

        // 3) The configurer has a built-in endpoints matcher we can get afterward
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // 4) Lock down those endpoints and finalize the SecurityFilterChain
        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .formLogin(Customizer.withDefaults())
                .oauth2ResourceServer(resourceServer ->
                        resourceServer
                                .jwt(jwt -> jwt.decoder(jwtDecoder)));

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public AuthenticationProvider oAuth2ClientCredentialsAuthenticationProvider() {

        return new OAuth2ClientCredentialsAuthenticationProvider(
                authorizationService(),
                tokenGenerator()
        );
    }

    // Example: A user who can log in
    @Bean("userDetailsService")
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {

        return new InMemoryUserDetailsManager(
                User.withUsername("testuser")
                        .password(passwordEncoder.encode("password"))
                        .roles("USER")
                        .build()
        );
    }

    // If you explicitly need an AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(
            HttpSecurity http,
            @Qualifier("userDetailsService") UserDetailsService userDetailsService) throws Exception {

        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService);

        return builder.build();
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {

        return new DelegatingOAuth2TokenGenerator(
                new OAuth2AccessTokenGenerator(),
                new OAuth2RefreshTokenGenerator()
//                new OidcIdTokenGenerator() // if you want OIDC
        );
    }

    @Bean("registeredClientRepository")
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        // Example single client
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret(passwordEncoder.encode("demo-secret"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8090/bly/auth/login/oauth2/code/demo-client")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .scope("openid")
                .scope("profile")
                .scope("read")
                .scope("write")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {

        return AuthorizationServerSettings.builder()
                .issuer("http://127.0.0.1:8090/bly/auth")
                .build();
    }
}

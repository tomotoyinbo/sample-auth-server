package io.pay.bly.authserver.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.ui.Model;

import java.util.Map;

@Controller
public class OAuth2CallbackController {

    @Value("${oauth2.client-id}")
    private String clientId;

    @Value("${oauth2.client-secret}")
    private String clientSecret;

    @Value("${oauth2.token-uri}")
    private String tokenUri;

    @Value("${oauth2.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/login/oauth2/code/demo-client")
    public String handleAuthorizationCodeCallback(
            @RequestParam("code") String authorizationCode,
            @RequestParam("state") String state,
            Model model) {

        // Exchange the authorization code for an access token
        ResponseEntity<Map> tokenResponse = exchangeAuthorizationCodeForToken(authorizationCode);

        if (tokenResponse.getStatusCode().is2xxSuccessful() && tokenResponse.getBody() != null) {
            Map<String, Object> tokenData = tokenResponse.getBody();

            // Extract tokens and additional data
            String accessToken = (String) tokenData.get("access_token");
            String refreshToken = (String) tokenData.get("refresh_token");
            String scope = (String) tokenData.get("scope");

            // Add the tokens to the model for rendering
            model.addAttribute("accessToken", accessToken);
            model.addAttribute("refreshToken", refreshToken);
            model.addAttribute("scope", scope);

            // Return a success page with token details
            return "oauth2-success";
        }

        // Handle errors
        model.addAttribute("error", "Failed to exchange authorization code for token");
        return "oauth2-error";
    }

    private ResponseEntity<Map> exchangeAuthorizationCodeForToken(String authorizationCode) {
        // Create the request payload
        String requestBody = UriComponentsBuilder.newInstance()
                .queryParam("grant_type", "authorization_code")
                .queryParam("code", authorizationCode)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .toUriString().substring(1); // Remove the leading "?" from the query string

        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");

        // Send the POST request to the token endpoint
        return restTemplate.postForEntity(tokenUri, new org.springframework.http.HttpEntity<>(requestBody, headers), Map.class);
    }
}

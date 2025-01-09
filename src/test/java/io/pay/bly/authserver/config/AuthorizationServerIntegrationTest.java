package io.pay.bly.authserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthorizationServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void clientCredentialsTokenSuccess() throws Exception {
        // For client_credentials, you typically POST to /oauth2/token with Basic auth
        mockMvc.perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION,
                                "Basic " + Base64.getEncoder()
                                        .encodeToString("demo-client:demo-secret".getBytes()))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.access_token").exists());
    }

    @Test
    void clientCredentialsTokenInvalidSecret() throws Exception {
        // Test invalid client secret
        mockMvc.perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION,
                                "Basic " + Base64.getEncoder()
                                        .encodeToString("demo-client:wrong-secret".getBytes()))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized());
    }

//    @Test
    void authorizationCodeFlowSuccess() throws Exception {
        // For Auth Code, you'd typically GET /oauth2/authorize with the relevant params
        // This is tricky to test fully with MockMvc since it involves redirects.
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-client")
                        .param("scope", "openid read")
                        .param("redirect_uri", "http://127.0.0.1:8090/login/oauth2/code/demo-client")
                        .with(user("testuser").password("password").roles("USER")))
                .andExpect(status().is3xxRedirection());
        // In a real test, you might parse the redirect location,
        // confirm there's a "code" param, etc.
    }
}

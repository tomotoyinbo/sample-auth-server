package io.pay.bly.authserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import static io.pay.bly.authserver.config.profile.Profile.NON_LOCAL;

@Configuration
@Profile(NON_LOCAL)
public class NonLocalConfig {
}

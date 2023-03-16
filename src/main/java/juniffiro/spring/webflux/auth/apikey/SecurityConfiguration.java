package juniffiro.spring.webflux.auth.apikey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         APIKeyManager apiKeyManager,
                                                         APIKeyConverter apiKeyConverter) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(apiKeyManager);
        authenticationWebFilter.setServerAuthenticationConverter(apiKeyConverter);

        return http.authorizeExchange()
                .anyExchange()
                .authenticated()
                  .and()
                 .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                    .httpBasic()
                        .disable()
                    .csrf()
                        .disable()
                    .formLogin()
                        .disable()
                    .logout()
                        .disable()
                    .build();
    }
}
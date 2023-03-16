package juniffiro.spring.webflux.auth.apikey;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class APIKeyManager implements ReactiveAuthenticationManager {

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.fromSupplier(() -> {
            if (authentication instanceof Key) {
                if (authentication.getCredentials() != null) {
                    authentication.setAuthenticated(true);
                }
            }
            return authentication;
        });
    }
}

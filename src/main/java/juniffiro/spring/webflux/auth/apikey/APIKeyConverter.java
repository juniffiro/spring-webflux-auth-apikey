package juniffiro.spring.webflux.auth.apikey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

@Component
public class APIKeyConverter implements ServerAuthenticationConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(APIKeyConverter.class);

    @Value("header")
    private String HEADER;
	
    @Value("key")
    private String API_KEY;

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        ServerHttpRequest httpRequest = exchange.getRequest();
        HttpHeaders httpHeaders = httpRequest.getHeaders();
        String apiKey = httpHeaders.getFirst(HEADER);
        InetSocketAddress remoteAddress = httpRequest.getRemoteAddress();
        if (remoteAddress == null || remoteAddress.getHostName() == null) {
            return Mono.empty();
        }
        if (apiKey == null || apiKey.isEmpty() || !apiKey.equals(API_KEY)) {
            LOGGER.warn("\n" +
                            "Try auth "
                            + "\n"
                            + "Host: " + remoteAddress.getHostName()
                            + "\n"
                            + "Path: " + httpRequest.getPath().value()
                            + "\n"
                            + "Method: " + httpRequest.getMethodValue()
                    );
            return Mono.empty();
        }
        return Mono.just(new Key(apiKey, ""));
    }
}

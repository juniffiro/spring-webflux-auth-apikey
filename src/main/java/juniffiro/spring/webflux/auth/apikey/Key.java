package juniffiro.spring.webflux.auth.apikey;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class Key implements Authentication {

    private String apiKey;
    private String name;
    private boolean authorized;

    public Key(String apiKey, String name) {
        this.apiKey = apiKey;
        this.name = name;
        this.authorized = false;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return apiKey;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return name;
    }

    @Override
    public boolean isAuthenticated() {
        return this.authorized;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authorized = isAuthenticated;
    }

    @Override
    public String getName() {
        return name;
    }
}

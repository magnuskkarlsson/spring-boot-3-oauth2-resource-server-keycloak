package se.mkk.springboot3oauth2resourceserverkeycloak;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class OAuth2ResourceServerSecurityConfig {

    // https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html#oauth2resourceserver-jwt-sansboot
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http //
                .authorizeHttpRequests(authorize -> authorize //
                        .anyRequest().authenticated()) //
                .oauth2ResourceServer(oauth2 -> oauth2 //
                        .jwt(jwt -> jwt //
                                .jwtAuthenticationConverter(this.jwtAuthenticationConverter())));
        return http.build();
    }

    // https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html#oauth2resourceserver-jwt-authorization-extraction
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakAuthoritiesConverter());
        return jwtAuthenticationConverter;
    }

    // Spring OAuth2 uses default Scopes Not Roles for Authorization
    // org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
    private class KeycloakAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            return convert(jwt.getClaims());
        }

        public Collection<GrantedAuthority> convert(Map<String, Object> claims) {
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            for (String authority : getAuthorities(claims)) {
                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + authority));
            }
            return grantedAuthorities;
        }

        private Collection<String> getAuthorities(Map<String, Object> claims) {
            Object realm_access = claims.get("realm_access");
            if (realm_access instanceof Map) {
                Map<String, Object> map = castAuthoritiesToMap(realm_access);
                Object roles = map.get("roles");
                if (roles instanceof Collection) {
                    return castAuthoritiesToCollection(roles);
                }
            }
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> castAuthoritiesToMap(Object authorities) {
            return (Map<String, Object>) authorities;
        }

        @SuppressWarnings("unchecked")
        private Collection<String> castAuthoritiesToCollection(Object authorities) {
            return (Collection<String>) authorities;
        }
    }
}

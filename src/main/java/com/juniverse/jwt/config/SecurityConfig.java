package com.juniverse.jwt.config;

import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Reglas de seguridad: API sin estado (sin sesión ni cookies), tokens Bearer validados por el
 * <i>resource server</i> de Spring Security, autorización por rutas y por métodos ({@code @PreAuthorize}).
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Cadena de filtros de seguridad.
     *
     * @param http configurador
     * @param accessTokenDecoder validador de tokens de acceso
     * @param handlers respuestas 401 y 403 en formato JSON
     * @return la cadena configurada
     * @throws Exception si falla la configuración
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, @Qualifier("accessTokenDecoder") JwtDecoder accessTokenDecoder,
            ProblemSecurityHandlers handlers) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // sin cookies de sesión no hay CSRF que prevenir
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/refresh", "/api/auth/validate").permitAll()
                        .requestMatchers("/api/public/**", "/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.decoder(accessTokenDecoder).jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(handlers)
                        .accessDeniedHandler(handlers))
                .exceptionHandling(e -> e.authenticationEntryPoint(handlers).accessDeniedHandler(handlers));
        return http.build();
    }

    /**
     * Convierte el claim {@code roles} del JWT en autoridades {@code ROLE_*} de Spring Security.
     *
     * @return convertidor
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    /**
     * Codificador de contraseñas (BCrypt con sal aleatoria). Nunca se guardan contraseñas en texto plano.
     *
     * @return codificador
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Usuarios de demostración en memoria (en un proyecto real vendrían de una base de datos).
     *
     * @param encoder codificador de contraseñas
     * @return servicio de usuarios
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        return new InMemoryUserDetailsManager(List.of(
                User.withUsername("user").password(encoder.encode("user123")).roles("USER").build(),
                User.withUsername("admin").password(encoder.encode("admin123")).roles("USER", "ADMIN").build()));
    }

    /**
     * Gestor que verifica usuario y contraseña en el login.
     *
     * @param userDetailsService usuarios
     * @param encoder codificador de contraseñas
     * @return gestor de autenticación
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(encoder);
        return new ProviderManager(provider);
    }
}

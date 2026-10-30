package com.juniverse.jwt.config;

import com.juniverse.jwt.token.RevokedTokens;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Infraestructura JWT: clave de firma, el codificador que GENERA tokens y dos decodificadores que los VALIDAN.
 * <ul>
 *   <li>{@code accessTokenDecoder}: el que usa Spring Security en cada petición; exige firma, expiración, emisor,
 *       que sea un token de <i>acceso</i> y que no esté revocado.</li>
 *   <li>{@code anyTokenDecoder}: solo firma, expiración y emisor; sirve para leer tokens de refresco y para el
 *       endpoint de validación.</li>
 * </ul>
 */
@Configuration
public class JwtConfig {

    /** Nombre del claim que distingue tokens de acceso y de refresco. */
    public static final String TOKEN_USE = "token_use";

    /**
     * Clave simétrica HS256. Falla al arrancar si la clave es demasiado corta (menos de 256 bits).
     *
     * @param properties propiedades JWT
     * @return la clave
     */
    @Bean
    public SecretKey jwtKey(JwtProperties properties) {
        byte[] bytes = properties.secret().getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret debe tener al menos 32 caracteres (256 bits) para HS256");
        }
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    /**
     * Codificador: firma los claims y produce el JWT compacto.
     *
     * @param key clave de firma
     * @return codificador
     */
    @Bean
    public JwtEncoder jwtEncoder(SecretKey key) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    /**
     * Decodificador básico (firma + expiración + emisor).
     *
     * @param key clave de firma
     * @param properties propiedades JWT
     * @return decodificador
     */
    @Bean
    public JwtDecoder anyTokenDecoder(SecretKey key, JwtProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder;
    }

    /**
     * Decodificador estricto para proteger los endpoints: además de lo básico exige {@code token_use=access} y
     * rechaza los tokens cuyo {@code jti} fue revocado (por ejemplo, tras un logout).
     *
     * @param key clave de firma
     * @param properties propiedades JWT
     * @param revoked lista de tokens revocados
     * @return decodificador
     */
    @Bean
    public JwtDecoder accessTokenDecoder(SecretKey key, JwtProperties properties, RevokedTokens revoked) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        OAuth2TokenValidator<Jwt> notRevoked = jwt -> revoked.isRevoked(jwt.getId())
                ? OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "El token fue revocado", null))
                : OAuth2TokenValidatorResult.success();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()),
                new JwtClaimValidator<String>(TOKEN_USE, "access"::equals),
                notRevoked));
        return decoder;
    }
}

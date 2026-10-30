package com.juniverse.jwt.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades {@code app.jwt.*}.
 *
 * @param secret clave secreta para firmar con HMAC-SHA256 (mínimo 32 caracteres; en producción viene de una variable de entorno)
 * @param issuer emisor que se escribe en el claim {@code iss} y se exige al validar
 * @param accessTtl vida del token de acceso (corta)
 * @param refreshTtl vida del token de refresco (larga)
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String secret, String issuer, Duration accessTtl, Duration refreshTtl) {
}

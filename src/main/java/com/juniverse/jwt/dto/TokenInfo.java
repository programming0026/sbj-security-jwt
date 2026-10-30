package com.juniverse.jwt.dto;

import java.time.Instant;
import java.util.List;

/**
 * Resultado de validar un token.
 *
 * @param valid si el token es válido ahora mismo
 * @param type "access" o "refresh"
 * @param subject usuario
 * @param roles roles (solo los tokens de acceso los llevan)
 * @param issuedAt emisión
 * @param expiresAt expiración
 * @param secondsRemaining segundos de vida restantes
 * @param reason motivo cuando no es válido
 */
public record TokenInfo(boolean valid, String type, String subject, List<String> roles, Instant issuedAt, Instant expiresAt,
        long secondsRemaining, String reason) {

    /**
     * Crea un resultado negativo.
     *
     * @param reason motivo
     * @return información de token inválido
     */
    public static TokenInfo invalid(String reason) {
        return new TokenInfo(false, null, null, List.of(), null, null, 0, reason);
    }
}

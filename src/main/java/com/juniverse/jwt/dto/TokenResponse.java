package com.juniverse.jwt.dto;

/**
 * Par de tokens que recibe el cliente.
 *
 * @param accessToken token de acceso (se envía como {@code Authorization: Bearer ...})
 * @param refreshToken token de refresco (solo se envía a /api/auth/refresh)
 * @param tokenType siempre "Bearer"
 * @param expiresIn segundos de vida del token de acceso
 * @param refreshExpiresIn segundos de vida del token de refresco
 */
public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn, long refreshExpiresIn) {
}

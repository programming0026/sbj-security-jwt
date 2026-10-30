package com.juniverse.jwt.dto;

/**
 * Petición de cierre de sesión.
 *
 * @param refreshToken token de refresco de la sesión (opcional pero recomendado, para revocar también la renovación)
 */
public record LogoutRequest(String refreshToken) {
}

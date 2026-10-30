package com.juniverse.jwt.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Petición para canjear un token de refresco.
 *
 * @param refreshToken token de refresco
 */
public record RefreshRequest(@NotBlank(message = "El refreshToken es obligatorio") String refreshToken) {
}

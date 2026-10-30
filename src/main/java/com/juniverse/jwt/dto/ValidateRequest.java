package com.juniverse.jwt.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Petición para validar un token.
 *
 * @param token JWT a validar
 */
public record ValidateRequest(@NotBlank(message = "El token es obligatorio") String token) {
}

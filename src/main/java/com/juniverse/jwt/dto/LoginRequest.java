package com.juniverse.jwt.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Credenciales de inicio de sesión.
 *
 * @param username usuario
 * @param password contraseña
 */
public record LoginRequest(
        @NotBlank(message = "El usuario es obligatorio") String username,
        @NotBlank(message = "La contraseña es obligatoria") String password) {
}

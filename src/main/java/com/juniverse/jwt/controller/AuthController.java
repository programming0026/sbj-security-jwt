package com.juniverse.jwt.controller;

import com.juniverse.jwt.dto.LoginRequest;
import com.juniverse.jwt.dto.LogoutRequest;
import com.juniverse.jwt.dto.RefreshRequest;
import com.juniverse.jwt.dto.TokenInfo;
import com.juniverse.jwt.dto.TokenResponse;
import com.juniverse.jwt.dto.ValidateRequest;
import com.juniverse.jwt.token.TokenService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints de autenticación: {@code /api/auth/login | refresh | validate | logout}. */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final TokenService tokens;

    /**
     * Crea el controlador.
     *
     * @param tokens servicio de tokens
     */
    public AuthController(TokenService tokens) {
        this.tokens = tokens;
    }

    /**
     * Genera los tokens a partir de usuario y contraseña (público).
     *
     * @param request credenciales
     * @return tokens de acceso y refresco
     */
    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return tokens.login(request.username(), request.password());
    }

    /**
     * Canjea un token de refresco por un par nuevo (público: el token de refresco ES la credencial).
     *
     * @param request token de refresco
     * @return nuevo par de tokens
     */
    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return tokens.refresh(request.refreshToken());
    }

    /**
     * Valida un token y devuelve su contenido (público). Responde 200 tanto si es válido como si no; mira el campo {@code valid}.
     *
     * @param request token a validar
     * @return información del token
     */
    @PostMapping("/validate")
    public TokenInfo validate(@Valid @RequestBody ValidateRequest request) {
        return tokens.validate(request.token());
    }

    /**
     * Cierra la sesión: revoca el token de acceso con el que se llama y la familia de refresco (requiere autenticación).
     *
     * @param jwt token de acceso actual
     * @param request token de refresco opcional
     */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal Jwt jwt, @RequestBody(required = false) LogoutRequest request) {
        tokens.logout(jwt.getId(), jwt.getExpiresAt(), request == null ? null : request.refreshToken());
    }
}

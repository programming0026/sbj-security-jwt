package com.juniverse.jwt.controller;

import com.juniverse.jwt.token.RefreshTokenStore;
import com.juniverse.jwt.token.RevokedTokens;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints de ejemplo con distintos niveles de protección: público, autenticado, por rol y por método. */
@RestController
@RequestMapping("/api")
public class ResourceController {

    private final RefreshTokenStore refreshTokens;
    private final RevokedTokens revokedTokens;

    /**
     * Crea el controlador.
     *
     * @param refreshTokens registro de tokens de refresco
     * @param revokedTokens lista negra
     */
    public ResourceController(RefreshTokenStore refreshTokens, RevokedTokens revokedTokens) {
        this.refreshTokens = refreshTokens;
        this.revokedTokens = revokedTokens;
    }

    /**
     * Público: no requiere token.
     *
     * @return respuesta fija
     */
    @GetMapping("/public/ping")
    public Map<String, String> ping() {
        return Map.of("status", "ok");
    }

    /**
     * Cualquier usuario autenticado: devuelve lo que dice su token.
     *
     * @param jwt token de acceso, inyectado por Spring Security
     * @return usuario, roles y fechas del token
     */
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        Instant expiresAt = jwt.getExpiresAt();
        return Map.of("username", jwt.getSubject(), "roles", roles, "tokenId", jwt.getId(), "expiresAt", String.valueOf(expiresAt));
    }

    /**
     * Seguridad por método: el propio usuario o un administrador. La expresión se evalúa antes de ejecutar el método.
     *
     * @param username usuario consultado
     * @return perfil de ejemplo
     */
    @GetMapping("/users/{username}/profile")
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public Map<String, String> profile(@PathVariable String username) {
        return Map.of("username", username, "profile", "Datos privados de " + username);
    }

    /**
     * Seguridad por ruta: solo rol ADMIN (regla en {@code SecurityConfig}).
     *
     * @return estadísticas de sesiones
     */
    @GetMapping("/admin/stats")
    public Map<String, Integer> stats() {
        return Map.of("activeRefreshSessions", refreshTokens.activeSessions(), "revokedAccessTokens", revokedTokens.size());
    }
}

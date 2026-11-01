package com.juniverse.jwt.token;

import com.juniverse.jwt.dto.TokenInfo;
import com.juniverse.jwt.dto.TokenResponse;
import com.juniverse.jwt.exception.InvalidTokenException;
import java.time.Instant;
import java.util.List;

/**
 * Contrato de TokenService.
 */
public interface TokenService {

    /**
     * Inicia sesión: verifica las credenciales y emite un par de tokens.
     *
     * @param username usuario
     * @param password contraseña
     * @return tokens de acceso y de refresco
     * @throws org.springframework.security.core.AuthenticationException si las credenciales son incorrectas
     */
    TokenResponse login(String username, String password);

    /**
     * Refresca la sesión: canjea un token de refresco válido por un par nuevo (y el viejo queda inutilizable).
     *
     * @param refreshToken token de refresco
     * @return nuevo par de tokens
     * @throws InvalidTokenException si el token es inválido, expiró, no es de refresco, ya se usó o fue revocado
     */
    TokenResponse refresh(String refreshToken);

    /**
     * Valida un token (de acceso o de refresco) y describe su contenido; nunca lanza excepción por un token malo.
     *
     * @param token texto del JWT
     * @return información del token, con {@code valid=false} y el motivo si no es válido
     */
    TokenInfo validate(String token);

    /**
     * Cierra la sesión: revoca el token de acceso actual y toda la familia de tokens de refresco.
     *
     * @param accessJti {@code jti} del token de acceso con el que se hace la petición
     * @param accessExpiresAt expiración de ese token de acceso
     * @param refreshToken token de refresco de la sesión (opcional)
     */
    void logout(String accessJti, Instant accessExpiresAt, String refreshToken);

    /**
     * Genera un token de ACCESO. Es público para poder emitir tokens con otra fecha en las pruebas.
     *
     * @param username usuario ({@code sub})
     * @param roles roles sin el prefijo {@code ROLE_}
     * @param issuedAt momento de emisión ({@code iat})
     * @return JWT firmado
     */
    String issueAccessToken(String username, List<String> roles, Instant issuedAt);

    /**
     * Genera un token de REFRESCO y lo registra. No lleva roles: solo identifica la sesión.
     *
     * @param username usuario ({@code sub})
     * @param family familia de la sesión
     * @param issuedAt momento de emisión
     * @return JWT firmado
     */
    String issueRefreshToken(String username, String family, Instant issuedAt);
}

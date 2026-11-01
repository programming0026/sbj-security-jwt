package com.juniverse.jwt.token;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Lista negra de tokens de acceso revocados (por su {@code jti}). Un JWT es válido hasta que expira, así que para
 * "cerrar sesión" de verdad hay que recordar los que se invalidaron. Cada entrada se elimina sola cuando el token
 * habría expirado de todos modos. En producción esto vive en Redis o en la base de datos.
 */
@Component
public class RevokedTokens {

    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    /**
     * Revoca un token hasta su fecha de expiración.
     *
     * @param jti identificador del token
     * @param expiresAt cuándo expira de forma natural
     */
    public void revoke(String jti, Instant expiresAt) {
        purge();
        revoked.put(jti, expiresAt);
    }

    public boolean isRevoked(String jti) {
        return jti != null && revoked.containsKey(jti);
    }

    /**
     * Cantidad de tokens revocados vigentes.
     *
     * @return tamaño de la lista
     */
    public int size() {
        purge();
        return revoked.size();
    }

    private void purge() {
        Instant now = Instant.now();
        revoked.values().removeIf(expiry -> expiry.isBefore(now));
    }
}

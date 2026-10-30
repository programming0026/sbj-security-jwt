package com.juniverse.jwt.token;

import com.juniverse.jwt.exception.InvalidTokenException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Registro de los tokens de refresco emitidos. Cada uno se puede usar UNA sola vez (rotación): al refrescar se entrega
 * uno nuevo de la misma "familia". Si alguien presenta un token que ya se usó, se asume que fue robado y se revoca
 * toda la familia (el atacante y el usuario legítimo deben iniciar sesión de nuevo).
 */
@Component
public class RefreshTokenStore {

    private record Entry(String username, String family, Instant expiresAt, boolean used) {
    }

    private final Map<String, Entry> tokens = new HashMap<>();

    /**
     * Registra un token de refresco recién emitido.
     *
     * @param jti identificador del token
     * @param username dueño
     * @param family familia (una por inicio de sesión)
     * @param expiresAt expiración
     */
    public synchronized void register(String jti, String username, String family, Instant expiresAt) {
        Instant now = Instant.now();
        tokens.values().removeIf(entry -> entry.expiresAt().isBefore(now));
        tokens.put(jti, new Entry(username, family, expiresAt, false));
    }

    /**
     * Consume un token de refresco: lo marca como usado y devuelve su familia.
     *
     * @param jti identificador del token
     * @return la familia a la que pertenece
     * @throws InvalidTokenException si no existe (desconocido o revocado) o ya fue usado (en ese caso revoca la familia)
     */
    public synchronized String consume(String jti) {
        Entry entry = tokens.get(jti);
        if (entry == null) {
            throw new InvalidTokenException("El token de refresco es desconocido o fue revocado");
        }
        if (entry.used()) {
            revokeFamily(entry.family());
            throw new InvalidTokenException("El token de refresco ya se usó: se cerraron todas las sesiones de esa familia");
        }
        tokens.put(jti, new Entry(entry.username(), entry.family(), entry.expiresAt(), true));
        return entry.family();
    }

    /**
     * Comprueba si un token de refresco sigue pudiendo usarse (sin consumirlo).
     *
     * @param jti identificador del token
     * @return {@code true} si existe y no se ha usado
     */
    public synchronized boolean isUsable(String jti) {
        Entry entry = tokens.get(jti);
        return entry != null && !entry.used();
    }

    /**
     * Revoca todos los tokens de una familia (cierre de sesión).
     *
     * @param family familia
     */
    public synchronized void revokeFamily(String family) {
        tokens.values().removeIf(entry -> entry.family().equals(family));
    }

    /**
     * Familia de un token registrado.
     *
     * @param jti identificador del token
     * @return la familia, o {@code null} si no existe
     */
    public synchronized String familyOf(String jti) {
        Entry entry = tokens.get(jti);
        return entry == null ? null : entry.family();
    }

    /**
     * Cantidad de sesiones activas (tokens de refresco sin usar).
     *
     * @return número de tokens utilizables
     */
    public synchronized int activeSessions() {
        return (int) tokens.values().stream().filter(entry -> !entry.used()).count();
    }
}

package com.juniverse.jwt.token;

import com.juniverse.jwt.config.JwtConfig;
import com.juniverse.jwt.config.JwtProperties;
import com.juniverse.jwt.dto.TokenInfo;
import com.juniverse.jwt.dto.TokenResponse;
import com.juniverse.jwt.exception.InvalidTokenException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;

/**
 * Ciclo de vida de los tokens: <b>generar</b> (login), <b>refrescar</b> (con rotación), <b>validar</b> y <b>revocar</b> (logout).
 * Se usan dos tokens: uno de acceso, corto, que viaja en cada petición, y uno de refresco, largo, que solo sirve para
 * pedir un par nuevo. Así, si roban el de acceso, el daño dura pocos minutos.
 */
@Service
public class JwtTokenService implements TokenService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtEncoder encoder;
    private final JwtDecoder anyTokenDecoder;
    private final JwtProperties properties;
    private final RefreshTokenStore refreshTokens;
    private final RevokedTokens revokedTokens;

    /**
     * Crea el servicio.
     *
     * @param authenticationManager verifica usuario y contraseña
     * @param userDetailsService consulta usuarios (para recargar sus roles al refrescar)
     * @param encoder firma los tokens
     * @param anyTokenDecoder lee tokens (firma, expiración, emisor)
     * @param properties propiedades JWT
     * @param refreshTokens registro de tokens de refresco
     * @param revokedTokens lista negra de tokens de acceso
     */
    public JwtTokenService(AuthenticationManager authenticationManager, UserDetailsService userDetailsService, JwtEncoder encoder,
            @Qualifier("anyTokenDecoder") JwtDecoder anyTokenDecoder, JwtProperties properties,
            RefreshTokenStore refreshTokens, RevokedTokens revokedTokens) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.encoder = encoder;
        this.anyTokenDecoder = anyTokenDecoder;
        this.properties = properties;
        this.refreshTokens = refreshTokens;
        this.revokedTokens = revokedTokens;
    }

    /**
     * Inicia sesión: verifica las credenciales y emite un par de tokens.
     *
     * @param username usuario
     * @param password contraseña
     * @return tokens de acceso y de refresco
     * @throws org.springframework.security.core.AuthenticationException si las credenciales son incorrectas
     */
    @Override
    public TokenResponse login(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, password));
        return issuePair(authentication.getName(), rolesOf(authentication.getAuthorities()), UUID.randomUUID().toString(), Instant.now());
    }

    /**
     * Refresca la sesión: canjea un token de refresco válido por un par nuevo (y el viejo queda inutilizable).
     *
     * @param refreshToken token de refresco
     * @return nuevo par de tokens
     * @throws InvalidTokenException si el token es inválido, expiró, no es de refresco, ya se usó o fue revocado
     */
    @Override
    public TokenResponse refresh(String refreshToken) {
        Jwt jwt = decode(refreshToken);
        if (!"refresh".equals(jwt.getClaimAsString(JwtConfig.TOKEN_USE))) {
            throw new InvalidTokenException("Se esperaba un token de refresco");
        }
        String family = refreshTokens.consume(jwt.getId());
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(jwt.getSubject());
        } catch (UsernameNotFoundException e) {
            refreshTokens.revokeFamily(family);
            throw new InvalidTokenException("El usuario del token ya no existe");
        }
        // Los roles se leen de nuevo: si cambiaron desde el login, el token nuevo ya los refleja
        return issuePair(user.getUsername(), rolesOf(user.getAuthorities()), family, Instant.now());
    }

    /**
     * Valida un token (de acceso o de refresco) y describe su contenido; nunca lanza excepción por un token malo.
     *
     * @param token texto del JWT
     * @return información del token, con {@code valid=false} y el motivo si no es válido
     */
    @Override
    public TokenInfo validate(String token) {
        Jwt jwt;
        try {
            jwt = anyTokenDecoder.decode(token);
        } catch (JwtException e) {
            return TokenInfo.invalid("Token inválido o expirado");
        }
        String type = jwt.getClaimAsString(JwtConfig.TOKEN_USE);
        if ("access".equals(type) && revokedTokens.isRevoked(jwt.getId())) {
            return TokenInfo.invalid("El token de acceso fue revocado");
        }
        if ("refresh".equals(type) && !refreshTokens.isUsable(jwt.getId())) {
            return TokenInfo.invalid("El token de refresco ya se usó o fue revocado");
        }
        long remaining = Math.max(0, Duration.between(Instant.now(), jwt.getExpiresAt()).toSeconds());
        List<String> roles = jwt.getClaimAsStringList("roles");
        return new TokenInfo(true, type, jwt.getSubject(), roles == null ? List.of() : roles, jwt.getIssuedAt(), jwt.getExpiresAt(), remaining, null);
    }

    /**
     * Cierra la sesión: revoca el token de acceso actual y toda la familia de tokens de refresco.
     *
     * @param accessJti {@code jti} del token de acceso con el que se hace la petición
     * @param accessExpiresAt expiración de ese token de acceso
     * @param refreshToken token de refresco de la sesión (opcional)
     */
    @Override
    public void logout(String accessJti, Instant accessExpiresAt, String refreshToken) {
        revokedTokens.revoke(accessJti, accessExpiresAt);
        if (refreshToken != null && !refreshToken.isBlank()) {
            try {
                Jwt jwt = anyTokenDecoder.decode(refreshToken);
                String family = refreshTokens.familyOf(jwt.getId());
                if (family != null) {
                    refreshTokens.revokeFamily(family);
                }
            } catch (JwtException ignored) {
                // un token de refresco ya inválido no necesita revocarse
            }
        }
    }

    /**
     * Genera un token de ACCESO. Es público para poder emitir tokens con otra fecha en las pruebas.
     *
     * @param username usuario ({@code sub})
     * @param roles roles sin el prefijo {@code ROLE_}
     * @param issuedAt momento de emisión ({@code iat})
     * @return JWT firmado
     */
    @Override
    public String issueAccessToken(String username, List<String> roles, Instant issuedAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(username)
                .id(UUID.randomUUID().toString())
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plus(properties.accessTtl()))
                .claim("roles", roles)
                .claim(JwtConfig.TOKEN_USE, "access")
                .build();
        return sign(claims);
    }

    /**
     * Genera un token de REFRESCO y lo registra. No lleva roles: solo identifica la sesión.
     *
     * @param username usuario ({@code sub})
     * @param family familia de la sesión
     * @param issuedAt momento de emisión
     * @return JWT firmado
     */
    @Override
    public String issueRefreshToken(String username, String family, Instant issuedAt) {
        String jti = UUID.randomUUID().toString();
        Instant expiresAt = issuedAt.plus(properties.refreshTtl());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(username)
                .id(jti)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim(JwtConfig.TOKEN_USE, "refresh")
                .build();
        refreshTokens.register(jti, username, family, expiresAt);
        return sign(claims);
    }

    private TokenResponse issuePair(String username, List<String> roles, String family, Instant now) {
        return new TokenResponse(issueAccessToken(username, roles, now), issueRefreshToken(username, family, now), "Bearer",
                properties.accessTtl().toSeconds(), properties.refreshTtl().toSeconds());
    }

    private String sign(JwtClaimsSet claims) {
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).type("JWT").build(), claims)).getTokenValue();
    }

    private Jwt decode(String token) {
        try {
            return anyTokenDecoder.decode(token);
        } catch (JwtException e) {
            throw new InvalidTokenException("El token es inválido o está expirado");
        }
    }

    private static List<String> rolesOf(java.util.Collection<? extends GrantedAuthority> authorities) {
        // Spring Security 7 añade autoridades FACTOR_* (factor de autenticación usado) que no son roles y no deben ir al token
        return authorities.stream().map(GrantedAuthority::getAuthority).filter(a -> a.startsWith("ROLE_")).map(a -> a.substring(5)).sorted().toList();
    }
}

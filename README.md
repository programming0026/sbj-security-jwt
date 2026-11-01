# Spring Security con JWT: login, refresco, validación y logout

Ejemplo con **Spring Boot 4** (Spring Security 7) y **Java 21** de una API sin sesión protegida con **JSON Web Tokens**. Implementa el ciclo completo: **generar** el token (login), **refrescarlo** con rotación, **validarlo** y **revocarlo** (logout). Usa solo las clases JWT que trae Spring Security (Nimbus JOSE), sin librerías externas.

## Cómo funciona

```text
Cliente                                  API
  │  POST /api/auth/login (usuario+clave) │
  │ ────────────────────────────────────► │  verifica con BCrypt
  │ ◄──────── accessToken (15 min)        │  emite 2 JWT firmados con HS256
  │           refreshToken (7 días)       │
  │                                       │
  │  GET /api/me  Authorization: Bearer <accessToken>
  │ ────────────────────────────────────► │  filtro: firma, exp, iss, tipo, ¿revocado?
  │                                       │
  │  (el accessToken expira)              │
  │  POST /api/auth/refresh <refreshToken>│
  │ ────────────────────────────────────► │  consume el refresh (un solo uso) y entrega un par NUEVO
```

- **Token de acceso**: corto, va en cada petición; lleva usuario (`sub`), roles, `jti`, `iat`, `exp`, `iss` y `token_use=access`.
- **Token de refresco**: largo, solo sirve en `/api/auth/refresh`; `token_use=refresh`. No lleva roles: al refrescar se vuelven a leer del usuario.
- **Rotación y detección de robo**: cada refresh se usa una sola vez. Si alguien presenta uno ya usado, se revoca toda la familia (todas las renovaciones de ese login).
- **Logout real**: un JWT no se puede "borrar", así que se guarda el `jti` en una lista negra hasta que expire y se revoca la familia de refresco.

## Endpoints

| Método | Ruta | Acceso | Descripción |
|--------|------|--------|-------------|
| POST | `/api/auth/login` | público | **Genera** los tokens: `{"username","password"}` |
| POST | `/api/auth/refresh` | público | **Refresca**: `{"refreshToken"}` → par nuevo (el anterior queda inutilizable) |
| POST | `/api/auth/validate` | público | **Valida** `{"token"}`; responde `valid`, tipo, usuario, roles, expiración y segundos restantes (o el motivo) |
| POST | `/api/auth/logout` | autenticado | Revoca el token de acceso actual y, si se envía `{"refreshToken"}`, la sesión de refresco |
| GET | `/api/public/ping` | público | Ejemplo sin protección |
| GET | `/api/me` | autenticado | Muestra lo que dice el token |
| GET | `/api/users/{username}/profile` | autenticado | `@PreAuthorize`: el propio usuario o ADMIN |
| GET | `/api/admin/stats` | rol ADMIN | Regla por ruta; devuelve sesiones activas y tokens revocados |

Usuarios de demostración (en memoria, contraseñas con BCrypt): `user` / `user123` (rol USER) y `admin` / `admin123` (USER y ADMIN).

Errores: `401` sin token, token inválido/expirado/revocado o credenciales incorrectas (con cabecera `WWW-Authenticate`); `403` rol insuficiente; `400` datos inválidos. Todos en formato Problem Details.

## Estructura

```text
src/main/java/com/juniverse/jwt/
├── JwtApplication.java
├── config/
│   ├── SecurityConfig.java            # filtros, rutas, roles, BCrypt, usuarios, AuthenticationManager
│   ├── JwtConfig.java                 # clave, JwtEncoder y los dos JwtDecoder (acceso / cualquiera)
│   ├── JwtProperties.java             # app.jwt.*
│   └── ProblemSecurityHandlers.java   # 401 y 403 en JSON
├── token/
│   ├── TokenService.java              # contrato: login, refresh, validate, logout y emisión de tokens
│   ├── JwtTokenService.java           # implementación con Spring Security y JWT
│   ├── RefreshTokenStore.java         # un solo uso + familias
│   └── RevokedTokens.java             # lista negra de tokens de acceso
├── controller/                        # AuthController y ResourceController
├── dto/                               # peticiones y respuestas
└── exception/                         # InvalidTokenException y manejo de errores
```

## Requisitos

- JDK 21 y Maven 3.9 o superior.

## Ejecutar

```bash
mvn spring-boot:run
```

```bash
# 1. Generar tokens
curl -X POST http://localhost:8080/api/auth/login -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'

# 2. Usar el token de acceso
curl http://localhost:8080/api/me -H "Authorization: Bearer <accessToken>"
curl http://localhost:8080/api/admin/stats -H "Authorization: Bearer <accessToken>"

# 3. Validarlo
curl -X POST http://localhost:8080/api/auth/validate -H "Content-Type: application/json" -d '{"token":"<accessToken>"}'

# 4. Refrescar (cada refreshToken sirve una sola vez)
curl -X POST http://localhost:8080/api/auth/refresh -H "Content-Type: application/json" -d '{"refreshToken":"<refreshToken>"}'

# 5. Cerrar sesión
curl -X POST http://localhost:8080/api/auth/logout -H "Authorization: Bearer <accessToken>" \
     -H "Content-Type: application/json" -d '{"refreshToken":"<refreshToken>"}'
```

Puedes pegar cualquier token en <https://jwt.io> para ver su contenido (el payload solo está codificado en Base64, **no cifrado**: nunca guardes secretos en él).

## Configuración

| Propiedad | Descripción |
|-----------|-------------|
| `app.jwt.secret` | Clave de firma HS256, mínimo 32 caracteres (la aplicación no arranca con una más corta). **En producción usa la variable `JWT_SECRET`** y no la subas al repositorio |
| `app.jwt.issuer` | Emisor que se escribe y se exige (`iss`) |
| `app.jwt.access-ttl` / `refresh-ttl` | Vida de cada token (por defecto 15 minutos y 7 días) |

## Pruebas

```bash
mvn test
```

18 pruebas con la cadena de filtros real de Spring Security (`MockMvc` + `springSecurity()`): login correcto, credenciales malas y validación; rutas públicas y protegidas, roles, `@PreAuthorize`, token basura, **manipulado**, firmado con **otra clave** y **expirado**; que un refresh no sirve como acceso; rotación, **reutilización de un refresh** (revoca la familia), refresh expirado; validación de tokens; logout; y rechazo de una clave débil.

## Lo que hay que mejorar antes de producción

- **Usuarios**: aquí están en memoria; usa una base de datos (`UserDetailsService` propio) y roles gestionados.
- **Estado**: `RefreshTokenStore` y `RevokedTokens` están en memoria y se pierden al reiniciar o no se comparten entre instancias; usa Redis o una tabla.
- **Firma**: HS256 comparte una clave entre emisor y verificadores. Con varios servicios usa **RS256/ES256** (clave privada para firmar, pública para verificar, JWKS).
- **Transporte**: solo por HTTPS; limita los intentos de login (fuerza bruta) y registra los accesos.
- **Cliente**: guarda el refresh en una cookie `HttpOnly; Secure; SameSite` en lugar de `localStorage` para mitigar XSS.
- Ten en cuenta que Spring valida `exp` con 60 s de tolerancia de reloj por defecto.

Fat jar ejecutable: `mvn clean package` y `java -jar target/sbj-security-jwt-0.0.1-SNAPSHOT.jar`.

## Licencia

Código de ejemplo de uso libre con fines educativos.

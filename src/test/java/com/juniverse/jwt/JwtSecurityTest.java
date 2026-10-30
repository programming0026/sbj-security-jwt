package com.juniverse.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.juniverse.jwt.config.JwtConfig;
import com.juniverse.jwt.config.JwtProperties;
import com.juniverse.jwt.token.TokenService;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/** Pruebas de seguridad de extremo a extremo con la cadena de filtros real de Spring Security. */
@SpringBootTest
@DisplayName("Spring Security + JWT")
class JwtSecurityTest {

    @Autowired
    private WebApplicationContext context;
    @Autowired
    private TokenService tokenService;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(SecurityMockMvcConfigurers.springSecurity()).build();
    }

    private String login(String user, String password) throws Exception {
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    private static String field(String json, String name) {
        return JsonPath.read(json, "$." + name);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private String refreshBody(String refreshToken) {
        return "{\"refreshToken\":\"" + refreshToken + "\"}";
    }

    @Nested
    @DisplayName("Generar token (login)")
    class Login {

        @Test
        @DisplayName("credenciales correctas -> par de tokens")
        void success() throws Exception {
            mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"user\",\"password\":\"user123\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"))
                    .andExpect(jsonPath("$.accessToken").isString())
                    .andExpect(jsonPath("$.refreshToken").isString())
                    .andExpect(jsonPath("$.expiresIn").value(900));
        }

        @Test
        @DisplayName("contraseña o usuario incorrectos -> 401 con el mismo mensaje")
        void badCredentials() throws Exception {
            for (String body : List.of("{\"username\":\"user\",\"password\":\"mala\"}", "{\"username\":\"fantasma\",\"password\":\"x\"}")) {
                mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                        .andExpect(status().isUnauthorized())
                        .andExpect(jsonPath("$.detail").value("Usuario o contraseña incorrectos"));
            }
        }

        @Test
        @DisplayName("campos vacíos -> 400")
        void validation() throws Exception {
            mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.length()").value(2));
        }
    }

    @Nested
    @DisplayName("Proteger endpoints")
    class Protection {

        @Test
        @DisplayName("público sin token; protegido sin token -> 401 con WWW-Authenticate")
        void publicAndProtected() throws Exception {
            mvc.perform(get("/api/public/ping")).andExpect(status().isOk());
            mvc.perform(get("/api/me")).andExpect(status().isUnauthorized()).andExpect(header().string("WWW-Authenticate", "Bearer"));
        }

        @Test
        @DisplayName("con token de acceso se accede y se leen usuario y roles")
        void withToken() throws Exception {
            String token = field(login("admin", "admin123"), "accessToken");
            mvc.perform(get("/api/me").header("Authorization", bearer(token)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value("admin"))
                    .andExpect(jsonPath("$.roles[0]").value("ADMIN"));
        }

        @Test
        @DisplayName("rol insuficiente -> 403; ADMIN -> 200")
        void roles() throws Exception {
            String user = field(login("user", "user123"), "accessToken");
            String admin = field(login("admin", "admin123"), "accessToken");
            mvc.perform(get("/api/admin/stats").header("Authorization", bearer(user))).andExpect(status().isForbidden());
            mvc.perform(get("/api/admin/stats").header("Authorization", bearer(admin))).andExpect(status().isOk());
        }

        @Test
        @DisplayName("@PreAuthorize: uno mismo sí, otro usuario no, admin sí")
        void methodSecurity() throws Exception {
            String user = field(login("user", "user123"), "accessToken");
            String admin = field(login("admin", "admin123"), "accessToken");
            mvc.perform(get("/api/users/user/profile").header("Authorization", bearer(user))).andExpect(status().isOk());
            mvc.perform(get("/api/users/admin/profile").header("Authorization", bearer(user))).andExpect(status().isForbidden());
            mvc.perform(get("/api/users/user/profile").header("Authorization", bearer(admin))).andExpect(status().isOk());
        }

        @Test
        @DisplayName("token basura, manipulado o firmado con otra clave -> 401")
        void invalidTokens() throws Exception {
            String token = field(login("user", "user123"), "accessToken");
            String tampered = token.substring(0, token.length() - 3) + (token.endsWith("AAA") ? "BBB" : "AAA");

            NimbusJwtEncoder foreign = new NimbusJwtEncoder(new ImmutableSecret<>(
                    new SecretKeySpec("otra-clave-distinta-de-32-caracteres!!".getBytes(StandardCharsets.UTF_8), "HmacSHA256")));
            Instant now = Instant.now();
            String forged = foreign.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
                    JwtClaimsSet.builder().issuer("https://api.juniverse.com").subject("admin").issuedAt(now).expiresAt(now.plusSeconds(600))
                            .claim("roles", List.of("ADMIN")).claim(JwtConfig.TOKEN_USE, "access").id("x").build())).getTokenValue();

            for (String bad : List.of("basura", tampered, forged)) {
                mvc.perform(get("/api/me").header("Authorization", bearer(bad))).andExpect(status().isUnauthorized());
            }
        }

        @Test
        @DisplayName("token expirado -> 401")
        void expired() throws Exception {
            String expired = tokenService.issueAccessToken("user", List.of("USER"), Instant.now().minus(Duration.ofHours(2)));
            mvc.perform(get("/api/me").header("Authorization", bearer(expired)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string("WWW-Authenticate", "Bearer error=\"invalid_token\""));
        }

        @Test
        @DisplayName("un token de refresco no sirve como token de acceso")
        void refreshTokenIsNotAnAccessToken() throws Exception {
            String refresh = field(login("user", "user123"), "refreshToken");
            mvc.perform(get("/api/me").header("Authorization", bearer(refresh))).andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Refrescar token")
    class Refresh {

        @Test
        @DisplayName("se obtiene un par nuevo y distinto")
        void rotates() throws Exception {
            String first = login("user", "user123");
            String body = mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(field(first, "refreshToken"))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            assertNotEquals(field(first, "accessToken"), field(body, "accessToken"));
            assertNotEquals(field(first, "refreshToken"), field(body, "refreshToken"));
            mvc.perform(get("/api/me").header("Authorization", bearer(field(body, "accessToken")))).andExpect(status().isOk());
        }

        @Test
        @DisplayName("reutilizar un refresh ya usado -> 401 y se revoca toda la familia")
        void reuseDetection() throws Exception {
            String first = login("user", "user123");
            String used = field(first, "refreshToken");
            String second = mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(used)))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

            mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(used)))
                    .andExpect(status().isUnauthorized());
            // el refresh nuevo (legítimo) también quedó revocado por la sospecha de robo
            mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(field(second, "refreshToken"))))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("un token de acceso no sirve para refrescar; uno expirado tampoco")
        void wrongOrExpired() throws Exception {
            String access = field(login("user", "user123"), "accessToken");
            mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(access))).andExpect(status().isUnauthorized());

            String expired = tokenService.issueRefreshToken("user", "familia-x", Instant.now().minus(Duration.ofDays(30)));
            mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(expired))).andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Validar token")
    class Validate {

        private String validate(String token) throws Exception {
            return mvc.perform(post("/api/auth/validate").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + token + "\"}"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        }

        @Test
        @DisplayName("acceso válido: describe usuario, roles y tiempo restante")
        void validAccess() throws Exception {
            String json = validate(field(login("admin", "admin123"), "accessToken"));
            assertEquals(true, JsonPath.read(json, "$.valid"));
            assertEquals("access", field(json, "type"));
            assertEquals("admin", field(json, "subject"));
            assertEquals(List.of("ADMIN", "USER"), JsonPath.read(json, "$.roles"));
            int remaining = JsonPath.read(json, "$.secondsRemaining");
            org.junit.jupiter.api.Assertions.assertTrue(remaining > 800 && remaining <= 900);
        }

        @Test
        @DisplayName("refresco válido, y basura / expirado -> valid=false con motivo")
        void others() throws Exception {
            assertEquals("refresh", field(validate(field(login("user", "user123"), "refreshToken")), "type"));
            assertEquals(false, JsonPath.read(validate("basura"), "$.valid"));
            String expired = tokenService.issueAccessToken("user", List.of("USER"), Instant.now().minus(Duration.ofHours(2)));
            assertEquals(false, JsonPath.read(validate(expired), "$.valid"));
        }
    }

    @Nested
    @DisplayName("Cerrar sesión")
    class Logout {

        @Test
        @DisplayName("logout revoca el acceso y el refresco")
        void revokes() throws Exception {
            String tokens = login("user", "user123");
            String access = field(tokens, "accessToken");
            String refresh = field(tokens, "refreshToken");

            mvc.perform(post("/api/auth/logout").header("Authorization", bearer(access)).contentType(MediaType.APPLICATION_JSON).content(refreshBody(refresh)))
                    .andExpect(status().isNoContent());

            mvc.perform(get("/api/me").header("Authorization", bearer(access))).andExpect(status().isUnauthorized());
            mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(refresh))).andExpect(status().isUnauthorized());
            mvc.perform(post("/api/auth/validate").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + access + "\"}"))
                    .andExpect(jsonPath("$.valid").value(false));
        }

        @Test
        @DisplayName("logout exige estar autenticado")
        void requiresAuth() throws Exception {
            mvc.perform(post("/api/auth/logout")).andExpect(status().isUnauthorized());
        }
    }

    @Test
    @DisplayName("una clave de firma corta impide arrancar")
    void weakSecretIsRejected() {
        JwtProperties weak = new JwtProperties("corta", "iss", Duration.ofMinutes(1), Duration.ofDays(1));
        assertThrows(IllegalStateException.class, () -> new JwtConfig().jwtKey(weak));
    }
}

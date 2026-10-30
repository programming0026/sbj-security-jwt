package com.juniverse.jwt;

import com.juniverse.jwt.config.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/** API protegida con Spring Security y JWT: login, refresco, validación y cierre de sesión. */
@SpringBootApplication
@EnableConfigurationProperties(JwtProperties.class)
public class JwtApplication {

    /**
     * Arranca la aplicación.
     *
     * @param args argumentos de la línea de comandos
     */
    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }
}

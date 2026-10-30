package com.juniverse.jwt.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * Respuestas de seguridad en JSON ({@code application/problem+json}): 401 cuando falta o es inválido el token y 403 cuando
 * el usuario autenticado no tiene permiso. Los filtros de seguridad actúan antes de los controladores, por eso estos
 * errores no pasan por el {@code @RestControllerAdvice}.
 */
@Component
public class ProblemSecurityHandlers implements AuthenticationEntryPoint, AccessDeniedHandler {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        boolean badToken = exception instanceof OAuth2AuthenticationException;
        response.setHeader("WWW-Authenticate", badToken ? "Bearer error=\"invalid_token\"" : "Bearer");
        write(response, HttpStatus.UNAUTHORIZED, "No autenticado",
                badToken ? "El token es inválido, está expirado o fue revocado" : "Se requiere un token Bearer en la cabecera Authorization",
                request.getRequestURI());
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException {
        write(response, HttpStatus.FORBIDDEN, "Acceso denegado", "No tienes permisos para este recurso", request.getRequestURI());
    }

    private static void write(HttpServletResponse response, HttpStatus status, String title, String detail, String path) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/problem+json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"title\":\"" + title + "\",\"status\":" + status.value() + ",\"detail\":\"" + detail
                + "\",\"instance\":\"" + path.replace("\"", "") + "\"}");
    }
}

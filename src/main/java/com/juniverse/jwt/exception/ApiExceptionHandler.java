package com.juniverse.jwt.exception;

import java.net.URI;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/** Errores de los controladores en formato Problem Details (RFC 9457). */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * 401 por usuario o contraseña incorrectos. El mensaje es el mismo si falla el usuario o la contraseña, para no
     * revelar qué usuarios existen.
     *
     * @param e excepción de autenticación
     * @return problema
     */
    @ExceptionHandler({BadCredentialsException.class, AuthenticationException.class})
    public ProblemDetail badCredentials(AuthenticationException e) {
        return problem(HttpStatus.UNAUTHORIZED, "Credenciales inválidas", "Usuario o contraseña incorrectos");
    }

    /**
     * 401 por un token de refresco inválido.
     *
     * @param e excepción
     * @return problema
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail invalidToken(InvalidTokenException e) {
        return problem(HttpStatus.UNAUTHORIZED, "Token inválido", e.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {
        List<Map<String, String>> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(f -> Map.of("field", f.getField(), "message", String.valueOf(f.getDefaultMessage()))).toList();
        ProblemDetail body = problem(HttpStatus.BAD_REQUEST, "Error de validación", "Uno o más campos no son válidos");
        body.setProperty("errors", errors);
        return ResponseEntity.badRequest().body(body);
    }

    private static ProblemDetail problem(HttpStatus status, String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://api.juniverse.com/errors/" + status.value()));
        return problem;
    }
}

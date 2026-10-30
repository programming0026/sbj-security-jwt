package com.juniverse.jwt.exception;

/** El token de refresco no sirve (inválido, expirado, de otro tipo, ya usado o revocado). Se responde 401. */
public class InvalidTokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Crea la excepción.
     *
     * @param message motivo
     */
    public InvalidTokenException(String message) {
        super(message);
    }
}

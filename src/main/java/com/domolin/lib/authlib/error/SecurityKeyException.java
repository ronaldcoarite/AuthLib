package com.domolin.lib.authlib.error;

public class SecurityKeyException extends RuntimeException {
    public SecurityKeyException(String message) {
        super(message);
    }

    public SecurityKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityKeyException(Throwable cause) {
        super(cause);
    }
}

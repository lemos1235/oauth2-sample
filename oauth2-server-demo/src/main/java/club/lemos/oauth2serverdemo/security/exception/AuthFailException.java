package club.lemos.oauth2serverdemo.security.exception;

import org.springframework.security.core.AuthenticationException;

public class AuthFailException extends AuthenticationException {

    public AuthFailException(String msg, Throwable t) {
        super(msg, t);
    }

    public AuthFailException(String msg) {
        super(msg);
    }
}

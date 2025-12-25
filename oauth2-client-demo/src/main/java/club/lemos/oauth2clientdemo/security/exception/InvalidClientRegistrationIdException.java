package club.lemos.oauth2clientdemo.security.exception;

public class InvalidClientRegistrationIdException extends IllegalArgumentException {

    /**
     * @param message the exception message
     */
    public InvalidClientRegistrationIdException(String message) {
        super(message);
    }

}

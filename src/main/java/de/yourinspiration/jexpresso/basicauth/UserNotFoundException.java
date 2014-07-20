package de.yourinspiration.jexpresso.basicauth;

/**
 * Should be thrown if a user could not be found be the given username.
 * 
 * @author Marcel Härle
 *
 */
public class UserNotFoundException extends Exception {

    private static final long serialVersionUID = -7119183728405557748L;

    public UserNotFoundException(final String message) {
        super(message);
    }

    public UserNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

}

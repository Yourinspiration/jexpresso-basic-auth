package de.yourinspiration.jexpresso.basicauth.algorithm;

import org.pmw.tinylog.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Implementation of PBKDF2 to use in a
 * {@link de.yourinspiration.jexpresso.basisauth.impl.PBKDF2PasswordEncoder}.
 *
 * @author Michael Malcharek
 */
public class PBKDF2 {
    private static final String ALGORITHM_PBKDF2 = "PBKDF2WithHmacSHA1";
    private static final String ALGORITHM_SALT = "SHA1PRNG";
    private static final String DELIMITER = ":";
    private static final int ITERATIONS = 32000;

    public static boolean checkpw(String plainText, String encodedText) {
        String[] splitted = encodedText.split(DELIMITER);
        if (splitted.length != 2)
            return false;

        String salt = splitted[0];

        String encodedPlainText = hashpw(plainText, salt);
        return encodedText.equals(encodedPlainText);
    }

    public static String hashpw(String plainText, String base64salt) {
        char[] chars = plainText.toCharArray();
        byte[] salt = Base64.getDecoder().decode(base64salt);

        try {
            PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, 64 * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM_PBKDF2);
            byte[] encoded = skf.generateSecret(spec).getEncoded();

            return new Result(salt, encoded).toString();
        } catch (InvalidKeySpecException ex) {
            Logger.error("Error creating key for " + ALGORITHM_PBKDF2);
            return null;
        } catch (NoSuchAlgorithmException ex) {
            Logger.error("Error creating " + ALGORITHM_PBKDF2);
            return null;
        }
    }

    public static String gensalt() {
        try {
            SecureRandom sr = SecureRandom.getInstance(ALGORITHM_SALT);
            byte[] salt = new byte[16];
            sr.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt);
        } catch (NoSuchAlgorithmException ex) {
            Logger.error("Error creating " + ALGORITHM_SALT);
            return null;
        }
    }

    public static final class Result {
        private final String _salt;
        private final String _content;

        public Result(byte[] salt, byte[] content) {
            _salt = Base64.getEncoder().encodeToString(salt);
            _content = Base64.getEncoder().encodeToString(content);
        }

        @Override
        public String toString() {
            return _salt + DELIMITER + _content;
        }
    }
}

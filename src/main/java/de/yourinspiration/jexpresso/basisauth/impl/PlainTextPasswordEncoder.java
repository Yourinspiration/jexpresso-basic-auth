package de.yourinspiration.jexpresso.basisauth.impl;

import de.yourinspiration.jexpresso.basicauth.PasswordEncoder;

/**
 * A very simple password encoder that compares plain text strings without any
 * encryption.
 * 
 * @author Marcel Härle
 *
 */
public class PlainTextPasswordEncoder implements PasswordEncoder {

    @Override
    public boolean checkpw(final String plaintext, final String encoded) {
        return plaintext.equals(encoded);
    }

    @Override
    public String encode(String plaintext) {
        return plaintext;
    }

}
